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

static void nbd_trip(void *opaque)
{
  int res;
  struct fuse_chan *ch = (struct fuse_chan*)opaque;
  size_t bufsize = fuse_chan_bufsize(ch);
  char *buf = (char *) alloca(bufsize);

  res = fuse_chan_recv(&ch, buf, bufsize);

  if (res > 0)
    fuse_session_process(fuse_chan_session(ch), buf, res, ch);
}

static void nbd_read(void *opaque)
{
  struct fuse_chan *ch = opaque;
  qemu_coroutine_enter(qemu_coroutine_create(nbd_trip), ch);
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

  memset(&qopts, 0, sizeof(qopts));
  ret = fuse_opt_parse(&args, &qopts, fuse_qemu_opts, fuse_qemu_opt_proc);
  if(ret == -1)
    exit(EXIT_FAILURE);

  memset(&ctx, 0, sizeof(ctx));
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
  free(qopts.image);
  fuse_opt_free_args(&args);

  se = fuse_get_session(fuse);
  ch = fuse_session_next_chan(se, NULL);
  qemu_set_fd_handler2(fuse_chan_fd(ch), NULL, nbd_read, NULL, ch);

  do {
    main_loop_wait(false);
  }while (!fuse_session_exited(se));


  fuse_teardown(fuse, mountpoint);
  exit(EXIT_SUCCESS);
}
