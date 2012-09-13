/* 9p.h
 *
 * 9P statical interface definitions.
 */
#ifndef __9p_h__
#define __9p_h__
//#include <stdint.h>
#include <stddef.h>
#define P9_PATH_MAX     256
#define P9_FD_MAX       128
#define P9_IOHDRSZ      24
#define P9_READDIRHDRSZ 24
/* 9p qid types */
enum p9_qid_t {
  P9_QTDIR = 0x80,
  P9_QTAPPEND = 0x40,
  P9_QTEXCL = 0x20,
  P9_QTMOUNT = 0x10,
  P9_QTAUTH = 0x08,
  P9_QTTMP = 0x04,
  P9_QTSYMLINK = 0x02,
  P9_QTLINK = 0x01,
  P9_QTFILE = 0x00,
};

/* 9p modes */
enum {
  P9_OREAD = 0x00,
  P9_OWRITE = 0x01,
  P9_ORDWR = 0x02,
  P9_OEXEC = 0x03,
  P9_OEXCL = 0x04,
  P9_OTRUNC = 0x10,
  P9_OREXEC = 0x20,
  P9_ORCLOSE = 0x40,
  P9_OAPPEND = 0x80,
};

/* 9p permissions */
enum {
  P9_Dmdir = 0x80000000,
  P9_Dmappend = 0x40000000,
  P9_Dmexcl = 0x20000000,
  P9_Dmmount = 0x10000000,
  P9_Dmauth = 0x08000000,
  P9_Dmtmp = 0x04000000,
  /* 9P2000.u extensions */
  P9_Dmsymlink = 0x02000000,
  P9_Dmlink = 0x01000000,
  P9_Dmdevice = 0x00800000,
  P9_Dmnamedpipe = 0x00200000,
  P9_Dmsocket = 0x00100000,
  P9_Dmsetuid = 0x00080000,
  P9_Dmsetgid = 0x00040000,
};

/* 9p servers identifiers (think: inodes) */
struct p9_qid {
  unsigned char type;
  char pad[sizeof(int) - sizeof(char)];
  unsigned int version;
  unsigned long long path;
};
/* 9p position in dir buffer */
struct p9_rdir {
  int head;
  int tail;
  char *buf;
};
/* 9p file system metadata information */
struct p9_wstat {
  unsigned short size;
  unsigned short type;
  unsigned int dev;
  struct p9_qid qid;
  unsigned int mode;
  unsigned int atime;
  unsigned int mtime;
  char pad[sizeof(long long) - sizeof(int)];
  unsigned long long length;
  char *name;
  char *uid;
  char *gid;
  char *muid;
  char *extension;              /* 9p2000.u extensions */
  unsigned int n_uid;           /* 9p2000.u extensions */
  unsigned int n_gid;           /* 9p2000.u extensions */
  unsigned int n_muid;          /* 9p2000.u extensions */
  char pad2[sizeof(void *) - sizeof(unsigned)];
};

struct p9_fid;
struct p9_client;

/******************************************************************************/

static int p9_version(struct p9_client *c);
static struct p9_client *p9_client_create(grub_device_t dev, int dotu,
                                          size_t msize);

static struct p9_fid *p9_attach(struct p9_client *c, struct p9_fid *afid,
                                char *uname, unsigned n_uname, char *aname,
                                unsigned uid);
static int p9_clunk(struct p9_fid *fid);
static struct p9_fid *p9_walk(struct p9_fid *oldfid, const char *path,
                              int clone);
static int p9_open(struct p9_fid *fid, int mode);
static int p9_read(struct p9_fid *fid, char *data, unsigned long long offset,
                   unsigned count);
#if 0
static void p9_client_destroy(struct p9_client *c);
static int p9_write(struct p9_fid *fid, char *data, unsigned long long offset,
                    unsigned count);
static int p9_creat(struct p9_fid *fid, const char *name, unsigned perm,
                    int mode, char *extension);
static int p9_remove(struct p9_fid *fid);
static int p9_wstat(struct p9_fid *fid, struct p9_wstat *buf);
#endif
static int p9_stat(struct p9_fid *fid, struct p9_wstat *buf);

#endif
