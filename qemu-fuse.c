#define FUSE_USE_VERSION        26

#include <fuse.h>
#include <fuse/fuse_lowlevel.h>
#include <linux/fuse.h>

#include <getopt.h>
#include <block.h>
#include <libgen.h>

typedef struct _qemu_ctx {
  BlockDriverState *bs;
  int backing_file;
  char* backing_file_name;
  size_t size;

  Coroutine *recv_coroutine;

  CoMutex send_lock;
  Coroutine *send_coroutine;
}qemu_ctx;

static int
qemu_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
  int ret = -ENOENT;
  struct fuse_context* ctx = fuse_get_context();
  qemu_ctx* pd = (qemu_ctx*)ctx->private_data;

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
  qemu_ctx* pd = (qemu_ctx*)ctx->private_data;

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
  qemu_ctx* pd = (qemu_ctx*)fi->fh;

  if ( offset < pd->size ) {
    if ( (offset + size) > pd->size ) {
      size = (pd->size - offset);
    }

    ret = bdrv_read(pd->bs, offset/BDRV_SECTOR_SIZE, (uint8_t*)buf, pd->size/BDRV_SECTOR_SIZE);

    if(ret == 0){
      ret = size;
    }
  }
  return ret;
}



static int
qemu_fuse_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
  int ret = 0;
  qemu_ctx* pd = (qemu_ctx*)fi->fh;

  if ( offset < pd->size ) {
    if ( (offset + size) > pd->size ) {
      size = (pd->size - offset);
    }

    ret = bdrv_write(pd->bs, offset/BDRV_SECTOR_SIZE, (uint8_t*)buf, pd->size/BDRV_SECTOR_SIZE);
    
    if(ret == 0){
      ret = size;
    }
  }
  return ret;
}

static int
qemu_fuse_flush(const char *path, struct fuse_file_info *fi)
{
  qemu_ctx* pd = (qemu_ctx*)fi->fh;
  return bdrv_co_flush(pd->bs);
}

static int
qemu_fuse_getattr(const char *path, struct stat *buf)
{
  int ret = -ENOENT;
  struct fuse_context* ctx = fuse_get_context();
  qemu_ctx* pd = (qemu_ctx*)ctx->private_data;

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
  qemu_ctx* pd = (qemu_ctx*)ctx->private_data;

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
  qemu_ctx* pd = (qemu_ctx*)ctx->private_data;

  if(strcmp(path+1, pd->backing_file_name) == 0){
    ret = fchmod(pd->backing_file, mode);
  }
  return ret;
}

static struct fuse_operations qemu_fuse_operations = {
  .readdir = qemu_fuse_readdir,

  .open = qemu_fuse_open,
  .read = qemu_fuse_read,
  .write = qemu_fuse_write,
  .flush = qemu_fuse_flush,

  .getattr = qemu_fuse_getattr,
  .chown = qemu_fuse_chown,
  .chmod = qemu_fuse_chmod,
};

static int fuse_chan_co_recv(struct fuse_chan **ch, char *buf, size_t size)
{
  int ret;
  qemu_ctx *ctx = fuse_chan_data(*ch);
  ctx->recv_coroutine = qemu_coroutine_self();

  ret = fuse_chan_recv(ch,buf,size);

  ctx->recv_coroutine = NULL;
  return ret;
}

static void nbd_trip(void *opaque)
{
  int res;
  struct fuse_chan *ch = (struct fuse_chan*)opaque;
  size_t bufsize = fuse_chan_bufsize(ch);
  char *buf = (char *) alloca(bufsize);

  res = fuse_chan_co_recv(&ch, buf, bufsize);
  if (res > 0)
    fuse_session_process(fuse_chan_session(ch), buf, res, ch);
}

static int nbd_can_read(void *opaque)
{
#if 0
  struct fuse_chan *ch = opaque;
  qemu_ctx *ctx = fuse_chan_data(ch);
  return ctx->recv_coroutine?1:0;
#endif
  return 1;
}

static void nbd_read(void *opaque)
{
  struct fuse_chan *ch = opaque;
  qemu_ctx *ctx = fuse_chan_data(ch);
  if (ctx->recv_coroutine) {
    qemu_coroutine_enter(ctx->recv_coroutine, NULL);
  } else {
    qemu_coroutine_enter(qemu_coroutine_create(nbd_trip), ch);
  }
}

static void nbd_restart_write(void *opaque)
{
  struct fuse_chan *ch = opaque;
  qemu_ctx *ctx = fuse_chan_data(ch);
  qemu_coroutine_enter(ctx->send_coroutine, NULL);
}

static int qemu_fuse_kern_chan_read(struct fuse_chan **chp, char *buf, size_t size)
{
  struct fuse_chan *ch = *chp;
  int err;
  ssize_t res;
  struct fuse_session *se = fuse_chan_session(ch);
  assert(se != NULL);

restart:
  res = qemu_co_read(fuse_chan_fd(ch), buf, size);
  err = errno;

  if (fuse_session_exited(se))
    return 0;
  if (res == -1) {
    if (err == ENOENT)
      goto restart;

    if (err == ENODEV) {
      fuse_session_exit(se);
      return 0;
    }
    if (err != EINTR && err != EAGAIN)
      perror("fuse: reading device");
    return -err;
  }
  if ((size_t) res < sizeof(struct fuse_in_header)) {
    fprintf(stderr, "short read on fuse device\n");
    return -EIO;
  }
  return res;
}

static int qemu_fuse_kern_chan_write(struct fuse_chan *ch, const struct iovec iov[], size_t count)
{
  qemu_ctx *ctx = fuse_chan_data(ch);
  qemu_co_mutex_lock(&ctx->send_lock);
  qemu_set_fd_handler2(fuse_chan_fd(ch), nbd_can_read, nbd_read, nbd_restart_write, ch);
  ctx->send_coroutine = qemu_coroutine_self();

  if(iov){
    ssize_t res = qemu_co_writev(fuse_chan_fd(ch), (struct iovec*)iov, count);
    int err = errno;

    if (res == -1) {
      struct fuse_session *se = fuse_chan_session(ch);

      assert(se != NULL);

      if (!fuse_session_exited(se) && err != ENOENT)
        perror("fuse: writing device");
      return -err;
    }
  }

  ctx->send_coroutine = NULL;
  qemu_set_fd_handler2(fuse_chan_fd(ch), nbd_can_read, nbd_read, NULL, ch);
  qemu_co_mutex_unlock(&ctx->send_lock);
  return 0;
}

#define MIN_BUFSIZE 0x21000

static struct fuse_chan *qemu_fuse_kern_chan_new(int fd, void* user_data)
{
  struct fuse_chan_ops op = {
    .receive = qemu_fuse_kern_chan_read,
    .send = qemu_fuse_kern_chan_write,
  };
  size_t bufsize = getpagesize() + 0x1000;
  bufsize = bufsize < MIN_BUFSIZE ? MIN_BUFSIZE : bufsize;
  return fuse_chan_new(&op, fd, bufsize, user_data);
}

static qemu_ctx*
qemu_ctx_new(BlockDriverState *bs, const char* path)
{
  char* tmpname;
  qemu_ctx *ctx;
  ctx = g_malloc0(sizeof(qemu_ctx));
  ctx->bs = bs;
  bdrv_get_geometry(ctx->bs, &ctx->size);
  ctx->size *= BDRV_SECTOR_SIZE;
  qemu_co_mutex_init(&ctx->send_lock);
  ctx->backing_file = open(path,O_RDONLY);
  tmpname = strdup(path);
  ctx->backing_file_name = strdup(basename(tmpname));
  free(tmpname);
  return ctx;
}

static void qemu_fuse_main(struct fuse_args* args,
                               const struct fuse_operations *op,
                               void *user_data)
{
        int fd;
        struct fuse_chan *cho;
        struct fuse_chan *ch;
        struct fuse *fuse = NULL;
        int foreground;
        int res;
        char* mountpoint;
        size_t op_size = sizeof(*op);

        res = fuse_parse_cmdline(args, &mountpoint, NULL, &foreground);
        if (res == -1)
                goto out;

        do {
                fd = open("/dev/null", O_RDWR);
                if (fd > 2)
                        close(fd);
        } while (fd >= 0 && fd <= 2);

        cho = fuse_mount(mountpoint, args);
        if (!cho)
                goto err_free;

        ch = qemu_fuse_kern_chan_new(fuse_chan_fd(cho), user_data);
        if (!ch){
                ch = cho;
                goto err_unmount;
        }

        qemu_set_fd_handler2(fuse_chan_fd(ch), nbd_can_read, nbd_read, NULL, ch);

        fuse = fuse_new(ch, args, op, op_size, user_data);
        if (fuse == NULL)
                goto err_unmount;

#if 0
        res = fuse_daemonize(foreground);
        if (res == -1)
                goto err_unmount;
#endif

        res = fuse_set_signal_handlers(fuse_get_session(fuse));
        if (res == -1)
                goto err_unmount;

        do {
          main_loop_wait(false);
        } while (!fuse_session_exited(fuse_get_session(fuse)));


        fuse_remove_signal_handlers(fuse_get_session(fuse));
        fuse_chan_destroy(cho);
err_unmount:
        fuse_unmount(mountpoint, ch);
        if (fuse)
                fuse_destroy(fuse);
err_free:
        free(mountpoint);
out:
        return;
}


static void usage(const char *name)
{
    printf(
"Usage: %s [OPTIONS] FILE\n"
"QEMU Disk Network Block Device Server\n"
"\n"
"  -r, --read-only      export read-only\n"
"  -s, --snapshot       use snapshot file\n"
"  -n, --nocache        disable host cache\n"
"  -c, --connect=DEV    connect FILE to the local NBD device DEV\n"
"  -e, --shared=NUM     device can be shared by NUM ctxs (default '1')\n"
"  -v, --verbose        display extra debugging information\n"
"  -h, --help           display this help and exit\n"
"  -V, --version        output version information and exit\n"
"\n"
"Report bugs to <anthony@codemonkey.ws>\n"
    , name);
}

static void version(const char *name)
{
    printf(
"%s version 0.0.1\n"
"Written by Anthony Liguori.\n"
"\n"
"Copyright (C) 2006 Anthony Liguori <anthony@codemonkey.ws>.\n"
"This is free software; see the source for copying conditions.  There is NO\n"
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"
    , name);
}

int main(int argc, char **argv)
{
    BlockDriverState *bs;
    const char *sopt = "hVrsndo:";
    struct option lopt[] = {
        { "help", 0, NULL, 'h' },
        { "version", 0, NULL, 'V' },
        { "read-only", 0, NULL, 'r' },
        { "snapshot", 0, NULL, 's' },
        { "nocache", 0, NULL, 'n' },
        { "debug", 0, NULL, 'd' },
        { NULL, 0, NULL, 0 }
    };
    int ch;
    char *srcpath;
    int opt_ind = 0;
    int flags = BDRV_O_RDWR;
    int ret;
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    fuse_opt_add_arg(&args, argv[0]);
    qemu_ctx* ctx;

    while ((ch = getopt_long(argc, argv, sopt, lopt, &opt_ind)) != -1) {
        switch (ch) {
        case 's':
            flags |= BDRV_O_SNAPSHOT;
            break;
        case 'n':
            flags |= BDRV_O_NOCACHE | BDRV_O_CACHE_WB;
            break;
        case 'r':
            flags &= ~BDRV_O_RDWR;
            break;
        case 'V':
            version(argv[0]);
            exit(0);
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
            break;
        case 'd':
            fuse_opt_add_arg(&args, "-d");
            break;
        case 'o':
            fuse_opt_add_arg(&args, "-o");
            fuse_opt_add_arg(&args, argv[opt_ind]);
            break;
        case '?':
            printf("Invalid argument.\n"
                   "Try `%s --help' for more information.", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if ((argc - optind) != 2) {
      printf("Invalid number of argument.\n"
             "Try `%s --help' for more information.",
              argv[0]);
      exit(EXIT_FAILURE);
    }
    fuse_opt_insert_arg(&args, 1, argv[optind+1]);



    bdrv_init();
    atexit(bdrv_close_all);

    bs = bdrv_new("hda");
    srcpath = argv[optind];
    if ((ret = bdrv_open(bs, srcpath, flags, NULL)) < 0) {
        errno = -ret;
        printf("Failed to bdrv_open '%s'", argv[optind]);
        exit(EXIT_FAILURE);
    }

    ctx = qemu_ctx_new(bs, argv[optind]);

    qemu_init_main_loop();

#if 0
    if (chdir("/") < 0) {
        errno = -ret;
        printf("Could not chdir to root directory");
        exit(EXIT_FAILURE);
    }
#endif

    qemu_fuse_main(&args, &qemu_fuse_operations, ctx);
    fuse_opt_free_args(&args);

    exit(EXIT_SUCCESS);
}
