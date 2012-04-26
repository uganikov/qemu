#define FUSE_USE_VERSION        26

#include <fuse.h>
#include <fuse/fuse_lowlevel.h>
#include <linux/fuse.h>

#include <block.h>
#include <libgen.h>

typedef struct _qemu_ctx {
  BlockDriverState *bs;
  int backing_file;
  char* backing_file_name;
  size_t size;
}qemu_ctx;

typedef struct _fuse_chan_ctx {
  struct fuse_chan* orig;
  CoMutex send_lock;
  Coroutine *send_coroutine;
}fuse_chan_ctx;

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

    ret = bdrv_read(pd->bs, offset/BDRV_SECTOR_SIZE, (uint8_t*)buf, size/BDRV_SECTOR_SIZE);

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

    ret = bdrv_write(pd->bs, offset/BDRV_SECTOR_SIZE, (uint8_t*)buf, size/BDRV_SECTOR_SIZE);
    
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

static void fuse_trip(void *opaque)
{
  int res;
  struct fuse_chan *ch = (struct fuse_chan*)opaque;
  size_t bufsize = fuse_chan_bufsize(ch);
  char *buf = (char *) alloca(bufsize);

  res = fuse_chan_recv(&ch, buf, bufsize);

  if (res > 0)
    fuse_session_process(fuse_chan_session(ch), buf, res, ch);
}

static void fuse_read(void *opaque)
{
  struct fuse_chan *ch = opaque;
  qemu_coroutine_enter(qemu_coroutine_create(fuse_trip), ch);
}

enum  {
  KEY_HELP,
  KEY_VERSION,
};

struct qemu_opts {
  int readonly;
  int snapshot;
  int nocache;
  char *image;
};

#define QEMU_OPT(t, p) { t, offsetof(struct qemu_opts, p), 1 }

static const struct fuse_opt fuse_qemu_opts[] = {
  QEMU_OPT("ro",           readonly),
  QEMU_OPT("snapshot",     snapshot),
  QEMU_OPT("no_bdrv_cache",nocache),

  FUSE_OPT_KEY("ro",              FUSE_OPT_KEY_KEEP),
  FUSE_OPT_KEY("-h",              KEY_HELP),
  FUSE_OPT_KEY("--help",          KEY_HELP),
  FUSE_OPT_KEY("-V",              KEY_VERSION),
  FUSE_OPT_KEY("--version",       KEY_VERSION),
  FUSE_OPT_END
};

static void usage(const char *progname)
{
  fprintf(stderr,
          "usage: %s imagefile mountpoint [options]\n\n", progname);
  fprintf(stderr,
          "general options:\n"
          "    -o opt,[opt...]        mount options\n"
          "    -h   --help            print help\n"
          "    -V   --version         print version\n"
          "\n");
}

static void qemu_help(void)
{
  fprintf(stderr,
          "QEMU options:\n"
          "    -o snapshot            use snapshot file\n"
          "    -o no_bdrv_cache       foreground operation\n"
          "\n"
          );
}

static void qemu_version(const char *name)
{
  fprintf(stderr, "%s version: %s\n", name, QEMU_VERSION);
  fprintf(stderr, "Original written by Anthony Liguori as qemu-nbd.\n"
"\n"
"Copyright (C) 2006 Anthony Liguori <anthony@codemonkey.ws>.\n"
"This is free software; see the source for copying conditions.  There is NO\n"
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n\n");
}

static int fuse_qemu_opt_proc(void *data, const char *arg, int key,
                                struct fuse_args *outargs)
{
  struct qemu_opts *qopts = data;

  switch (key) {
  case KEY_HELP:
    usage(outargs->argv[0]);
    /* fall through */
    qemu_help();
    // KEY_HELP_NOHEADER for helper
    return fuse_opt_add_arg(outargs, "-ho");

  case KEY_VERSION:
    qemu_version(outargs->argv[0]);
    return 1;

  case FUSE_OPT_KEY_NONOPT:
    if (!qopts->image) {
      char image[PATH_MAX];
      if (realpath(arg, image) == NULL) {
        fprintf(stderr,
                "fuse: bad image file `%s': %s\n",
                arg, strerror(errno));
        return -1;
      }
      return fuse_opt_add_opt(&qopts->image, image);
    } else {
      return 1;
    }

  default:
    return 1;
  }
}

static int fuse_qemu_chan_receive(struct fuse_chan **chp, char *buf,
                                  size_t size)
{
        struct fuse_chan *ch = *chp;
        int err;
        ssize_t res;
        struct fuse_session *se = fuse_chan_session(ch);
        assert(se != NULL);

restart:
        res = read(fuse_chan_fd(ch), buf, size);
        err = errno;

        if (fuse_session_exited(se))
                return 0;
        if (res == -1) {
                /* ENOENT means the operation was interrupted, it's safe
                   to restart */
                if (err == ENOENT || err == EAGAIN){
//                        qemu_coroutine_yield();
                        goto restart;
                }

                if (err == ENODEV) {
                        fuse_session_exit(se);
                        return 0;
                }
                /* Errors occuring during normal operation: EINTR (read
                   interrupted), EAGAIN (nonblocking I/O), ENODEV (filesystem
                   umounted) */
                if (err != EINTR)
                        perror("fuse: reading device");
                return -err;
        }
        if ((size_t) res < sizeof(struct fuse_in_header)) {
                fprintf(stderr, "short read on fuse device\n");
                return -EIO;
        }
        return res;
}

static void fuse_restart_write(void *opaque)
{
    struct fuse_chan*  ch = (struct fuse_chan*)opaque;
    fuse_chan_ctx *ctx = (fuse_chan_ctx*)fuse_chan_data(ch);

    qemu_coroutine_enter(ctx->send_coroutine, NULL);
}

static int coroutine_fn qemu_co_writev(int sockfd, struct iovec *iov, int iovlen)
{
    int i;
    int total = 0;
    int ret;
    for (i =0 ; i < iovlen; i++) {
        ret = writev(sockfd, iov, iovlen);
        if (ret < 0) {
            if (errno == EAGAIN) {
                qemu_coroutine_yield();
                continue;
            }
            if (total == 0) {
                total = -1;
            }
            break;
        }
        total += ret;
    }

    return total;
}

static int fuse_qemu_chan_send(struct fuse_chan *ch, const struct iovec iov[],
                               size_t count)
{
        if (iov) {
                ssize_t res;
                fuse_chan_ctx* ctx = (fuse_chan_ctx*)fuse_chan_data(ch);

                qemu_co_mutex_lock(&ctx->send_lock);
                qemu_set_fd_handler2(fuse_chan_fd(ch), NULL, fuse_read, fuse_restart_write, ch);
                ctx->send_coroutine = qemu_coroutine_self();
 
                res = qemu_co_writev(fuse_chan_fd(ch), (struct iovec*)iov, count);
//                res = writev(fuse_chan_fd(ch), iov, count);
                int err = errno;

                if (res == -1) {
                        struct fuse_session *se = fuse_chan_session(ch);

                        assert(se != NULL);

                        /* ENOENT means the operation was interrupted */
                        if (!fuse_session_exited(se) && err != ENOENT)
                                perror("fuse: writing device");
                        return -err;
                }

                ctx->send_coroutine = NULL;
                qemu_set_fd_handler2(fuse_chan_fd(ch), NULL, fuse_read, NULL, ch);

                qemu_co_mutex_unlock(&ctx->send_lock);

        }
        return 0;
}

static void fuse_qemu_chan_destroy(struct fuse_chan *ch)
{
  fuse_chan_ctx *ctx = (fuse_chan_ctx*)fuse_chan_data(ch);
  fuse_chan_destroy(ctx->orig);
}

struct fuse_chan_ops qemu_chan_op = {
  .receive = fuse_qemu_chan_receive,
  .send = fuse_qemu_chan_send,
  .destroy = fuse_qemu_chan_destroy,
};

int main(int argc, char **argv)
{
  int ret;
  int flags;
  struct fuse *fuse;
  struct fuse_session *se;
  struct fuse_chan *ch;
  char *mountpoint;
  struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
  struct qemu_opts qopts;
  qemu_ctx ctx;
  fuse_chan_ctx chan_ctx;

  memset(&qopts, 0, sizeof(qopts));
  ret = fuse_opt_parse(&args, &qopts, fuse_qemu_opts, fuse_qemu_opt_proc);
  if(ret == -1)
    exit(EXIT_FAILURE);

  memset(&ctx, 0, sizeof(ctx));
  memset(&chan_ctx, 0, sizeof(chan_ctx));
  fuse = fuse_setup(args.argc, args.argv, &qemu_fuse_operations, sizeof(qemu_fuse_operations), &mountpoint, NULL, &ctx);
  if (fuse == NULL)
    exit(EXIT_FAILURE);

  // ここでは既にdaemonizeされている
  qemu_init_main_loop();

  flags  = BDRV_O_RDWR;
  if(qopts.snapshot)
    flags |= BDRV_O_SNAPSHOT;
  if(qopts.nocache)
    flags |= BDRV_O_NOCACHE | BDRV_O_CACHE_WB;
  if(qopts.readonly)
    flags &= ~BDRV_O_RDWR;

  bdrv_init();
  atexit(bdrv_close_all);

  ctx.bs = bdrv_new("hda");
  if ((ret = bdrv_open(ctx.bs, qopts.image, flags, NULL)) < 0) {
    errno = -ret;
    printf("Failed to bdrv_open '%s'", qopts.image);
    exit(EXIT_FAILURE);
  }

  bdrv_get_geometry(ctx.bs, &ctx.size);
  ctx.size *= BDRV_SECTOR_SIZE;
  ctx.backing_file = open(qopts.image,O_RDONLY);
  ctx.backing_file_name = strdup(basename(qopts.image));
  qemu_co_mutex_init(&chan_ctx.send_lock);
  
  free(qopts.image);
  fuse_opt_free_args(&args);

  se = fuse_get_session(fuse);
  chan_ctx.orig = fuse_session_next_chan(se, NULL);

  fuse_session_remove_chan(chan_ctx.orig);
  ch = fuse_chan_new(&qemu_chan_op, fuse_chan_fd(chan_ctx.orig), fuse_chan_bufsize(chan_ctx.orig), &chan_ctx);
  fuse_session_add_chan(se, ch);
  qemu_set_fd_handler2(fuse_chan_fd(ch), NULL, fuse_read, NULL, ch);

  do {
    main_loop_wait(false);
  }while (!fuse_session_exited(se));

  fuse_teardown(fuse, mountpoint);
  exit(EXIT_SUCCESS);
}
