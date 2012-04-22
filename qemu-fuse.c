#define FUSE_USE_VERSION	26

#include <fuse.h>
#include <block.h>
#include <libgen.h>
#include <pthread.h>

typedef struct _co_data{
  QSIMPLEQ_ENTRY(_co_data) entry;
  enum {
    CO_CMD_READ,
    CO_CMD_WRITE,
    CO_CMD_FLUSH,
  } cmd;
  BlockDriverState *bs;
  size_t size;
  off_t offset;
  int ret;
  uint8_t* buf;
  pthread_mutex_t cmd_cond_lock;
  pthread_cond_t cmd_cond;
} co_data;

typedef struct _priv_data{
  int running;
  int backing_file;
  char* backing_file_name;
  uint64_t size;
  pthread_mutex_t queue_lock;
  BlockDriverState *bs;
  QSIMPLEQ_HEAD(, _co_data) requests;
} priv_data;

static co_data*
fuse_request_get(priv_data* priv)
{
  co_data *co = NULL;

  pthread_mutex_lock(&priv->queue_lock);
  if(!QSIMPLEQ_EMPTY(&priv->requests)) {
    co = QSIMPLEQ_FIRST(&priv->requests);
    QSIMPLEQ_REMOVE_HEAD(&priv->requests, entry);
  }
  pthread_mutex_unlock(&priv->queue_lock);

  return co;
}

static void
fuse_request_put(priv_data* priv, co_data* co)
{
  pthread_mutex_lock(&priv->queue_lock);
  QSIMPLEQ_INSERT_TAIL(&priv->requests, co, entry);
  qemu_notify_event();
  pthread_mutex_unlock(&priv->queue_lock);
}

static int
qemu_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
  int ret = -ENOENT;
  struct fuse_context* ctx = fuse_get_context();
  priv_data* pd = (priv_data*)ctx->private_data;

  if (strcmp(path, "/") == 0){
    if(offset == 0){
      if(filler(buf, ".", NULL, ++offset)){
        offset = 0;
      }
    }
    if(offset == 1){
      if(filler(buf, "..", NULL, ++offset)){
        offset = 0;
      }
    }
    if(offset == 2){
      if(filler(buf, pd->backing_file_name, NULL, 0)){
        offset = 0;
      }
    }
    ret = 0;
  }
  return ret;
}

static int
qemu_fuse_open(const char *path, struct fuse_file_info *fi)
{
  int ret = -ENOENT;
  struct fuse_context* ctx = fuse_get_context();
  priv_data* pd = (priv_data*)ctx->private_data;

  if(strcmp(path+1, pd->backing_file_name) == 0){
    fi->fh = (uint64_t)pd;
    ret = 0;
  }
  return ret;
}

static int
qemu_fuse_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  int ret = 0;
  priv_data* pd = (priv_data*)fi->fh;

  if ( offset < pd->size ) {
    if ( (offset + size) > pd->size ) {
      size = (pd->size - offset);
    }
    co_data data;

    data.bs = pd->bs;
    data.size = size;
    data.offset = offset;
    data.buf = (uint8_t*)buf;
    data.cmd = CO_CMD_READ;

    pthread_mutex_init(&data.cmd_cond_lock, NULL);
    pthread_cond_init(&data.cmd_cond, NULL);
    pthread_mutex_lock(&data.cmd_cond_lock);

    fuse_request_put(pd, &data); 

    pthread_cond_wait(&data.cmd_cond, &data.cmd_cond_lock);
    pthread_mutex_unlock(&data.cmd_cond_lock);
    pthread_cond_destroy(&data.cmd_cond);
    pthread_mutex_destroy(&data.cmd_cond_lock);

    ret = data.ret;
    if(ret == 0){
      ret = size;
    }
  }
  return ret;
}

static void
qemu_fuse_co(void *opaque)
{
  co_data* data = (co_data*)opaque;
  switch(data->cmd){
  case CO_CMD_READ:
    data->ret = bdrv_read(data->bs, data->offset/BDRV_SECTOR_SIZE, (uint8_t*)data->buf, data->size/BDRV_SECTOR_SIZE);
    break;
  case CO_CMD_WRITE:
    data->ret = bdrv_write(data->bs, data->offset/BDRV_SECTOR_SIZE, (uint8_t*)data->buf, data->size/BDRV_SECTOR_SIZE);
    break;
  case CO_CMD_FLUSH:
    data->ret = bdrv_co_flush(data->bs);
    break;
  }

  pthread_mutex_lock(&data->cmd_cond_lock);
  pthread_cond_signal(&data->cmd_cond);
  pthread_mutex_unlock(&data->cmd_cond_lock);
}

static int
qemu_fuse_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  int ret = 0;
  priv_data* pd = (priv_data*)fi->fh;

  if ( offset < pd->size ) {
    if ( (offset + size) > pd->size ) {
      size = (pd->size - offset);
    }
    co_data data;

    data.bs = pd->bs;
    data.size = size;
    data.offset = offset;
    data.buf = (uint8_t*)buf;
    data.cmd = CO_CMD_WRITE;

    pthread_mutex_init(&data.cmd_cond_lock, NULL);
    pthread_cond_init(&data.cmd_cond, NULL);
    pthread_mutex_lock(&data.cmd_cond_lock);

    fuse_request_put(pd, &data);

    pthread_cond_wait(&data.cmd_cond, &data.cmd_cond_lock);
    pthread_mutex_unlock(&data.cmd_cond_lock);
    pthread_cond_destroy(&data.cmd_cond);
    pthread_mutex_destroy(&data.cmd_cond_lock);

    ret = data.ret;
    if(ret == 0){
      ret = size;
    }
  }
  return ret;
}

static int
qemu_fuse_flush(const char *path, struct fuse_file_info *fi)
{
  priv_data* pd = (priv_data*)fi->fh;
  co_data data;

  data.bs = pd->bs;
  data.ret = -1;
  data.cmd = CO_CMD_FLUSH;

  pthread_mutex_init(&data.cmd_cond_lock, NULL);
  pthread_cond_init(&data.cmd_cond, NULL);
  pthread_mutex_lock(&data.cmd_cond_lock);

  fuse_request_put(pd, &data);

  pthread_cond_wait(&data.cmd_cond, &data.cmd_cond_lock);
  pthread_mutex_unlock(&data.cmd_cond_lock);
  pthread_cond_destroy(&data.cmd_cond);
  pthread_mutex_destroy(&data.cmd_cond_lock);

  return data.ret;
}

static int
qemu_fuse_getattr(const char *path, struct stat *buf)
{
  int ret = -ENOENT;
  struct fuse_context* ctx = fuse_get_context();
  priv_data* pd = (priv_data*)ctx->private_data;

  memset(buf, 0, sizeof(struct stat));

  if (strcmp(path, "/") == 0) {
    buf->st_mode = S_IFDIR | 0755;
    buf->st_nlink = 2;
    ret = 0;
  }else if(strcmp(path+1, pd->backing_file_name) == 0){
    ret = fstat(pd->backing_file, buf);
    buf->st_size = pd->size;
  }
  return ret;
}

static int
qemu_fuse_chown(const char *path, uid_t uid, gid_t gid)
{
  int ret = -ENOENT;
  struct fuse_context* ctx = fuse_get_context();
  priv_data* pd = (priv_data*)ctx->private_data;

  if(strcmp(path+1, pd->backing_file_name) == 0){
    ret = fchown(pd->backing_file, uid, gid);
  }
  return ret;
}

static int
qemu_fuse_chmod(const char *path, mode_t mode)
{
  int ret = -ENOENT;
  struct fuse_context* ctx = fuse_get_context();
  priv_data* pd = (priv_data*)ctx->private_data;

  if(strcmp(path+1, pd->backing_file_name) == 0){
    ret = fchmod(pd->backing_file, mode);
  }
  return ret;
}

static struct fuse_operations qemu_fuse_operations = {
  .readdir = qemu_fuse_readdir,

  .open	= qemu_fuse_open,
  .read	= qemu_fuse_read,
  .write = qemu_fuse_write,
  .flush = qemu_fuse_flush,

  .getattr = qemu_fuse_getattr,
  .chown = qemu_fuse_chown,
  .chmod = qemu_fuse_chmod,
};

static void*
qemu_loop(void* arg)
{
  priv_data* pd = (priv_data*)arg;

  // signal .. fuse...
  qemu_init_main_loop();
  while(pd->running){
    co_data* co = fuse_request_get(pd);
    if(co){
      qemu_coroutine_enter(qemu_coroutine_create(qemu_fuse_co), co);
    }else{
      main_loop_wait(false);
    }
  }
  return NULL;
}

static int
fuse_main_and_create_qemu_thread(int argc, char *argv[], const struct fuse_operations *op, void* user_data)
{
  priv_data *pd;
  struct fuse *fuse;
  char *mountpoint;
  int multithreaded;
  int res;
  pthread_t qemu_thread;

  pd = (priv_data*)user_data;
  fuse = fuse_setup(argc, argv, op, sizeof(*op), &mountpoint, &multithreaded, user_data);
  if (fuse == NULL)
    return 1;

  pthread_create(&qemu_thread, NULL, qemu_loop, user_data);

  if (multithreaded)
    res = fuse_loop_mt(fuse);
  else
    res = fuse_loop(fuse);

  fuse_teardown(fuse, mountpoint);

  pd->running = 0;
  pthread_join(qemu_thread, NULL);

  if (res == -1)
    return 1;

  return 0;
}

int
main(int argc, char *argv[])
{
  priv_data pd;
  struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
  int i;
  int ret = -1;
 
  memset(&pd, 0, sizeof(pd));
  pd.backing_file = -1;
    
  fuse_opt_add_arg(&args, argv[0]);
  for(i = 1; i < argc; i++) {
    if (argv[i][0]!='-' && pd.backing_file == -1) { 
      char* tmpname = strdup(argv[i]);
      pd.backing_file = open(argv[i],O_RDONLY);
      pd.backing_file_name = strdup(basename(tmpname));
      free(tmpname);

      pd.running = 1;
      QSIMPLEQ_INIT(&pd.requests);
      pthread_mutex_init(&pd.queue_lock, NULL);

      bdrv_init();
      atexit(bdrv_close_all);

      pd.bs = bdrv_new("");
      if ((ret = bdrv_open(pd.bs, argv[i], BDRV_O_RDWR, NULL)) == 0) {
        bdrv_get_geometry(pd.bs, &pd.size);
        pd.size *= BDRV_SECTOR_SIZE;
      }
    } else {
      fuse_opt_add_arg(&args, argv[i]);
    }
  }
  if(ret == 0){
    ret = fuse_main_and_create_qemu_thread(args.argc, args.argv, &qemu_fuse_operations, &pd);
    pthread_mutex_lock(&pd.queue_lock);
    pthread_mutex_unlock(&pd.queue_lock);
    pthread_mutex_destroy(&pd.queue_lock);
    if(pd.backing_file != -1) close(pd.backing_file);
    if(pd.backing_file_name) free(pd.backing_file_name);
  }
  return ret;
}
