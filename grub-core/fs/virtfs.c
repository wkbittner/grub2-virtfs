/* 
 *
 * virtfs.c: virtfs file system for grub
 * authors: William K. Bittner <wkbittne@us.ibm.com>
 *          Natalie Orlin <norlin@us.ibm.com>
 *
 * 9P Client code
 *  Based on code from Eric Van Hensbergen <ericvanhensbergen@us.ibm.com>
 *  Base on code from Anthony Liguori <aliguori@us.ibm.com>
 *
 * Copyright (C) 2011 by IBM, Corp.
 * 
 */

#include <grub/err.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/misc.h>
#include <grub/disk.h>
#include <grub/dl.h>
#include <grub/types.h>
#include <grub/lib/hexdump.h>
#define GRUB_virtfs_MAGIC 0x31457

#include <9p/9p.h>
#include <9p/protocol.h>
#include <9p/client.h>
#include <9p/trans.h>
#include <9p/endian.h>

#include <grub/pci.h>
#include <grub/misc.h>
#include <grub/virtio-pci.h>
#include <grub/virtio-ring.h>
#include <grub/time.h>

GRUB_MOD_LICENSE("GPLv3+");

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif
#define USED(x) (x = x)
#define BUG() { \
   grub_dprintf("virtfs","BUG: failure at %s:%d/%s()!\n", \
          __FILE__, __LINE__, __FUNCTION__); \
}
#define BUG_ON(condition) do { if (condition) BUG(); } while (0)

#define P9_TAG_MAX  1
#define P9_START_FID 	1
#define P9_MSIZE	4096

#define MAX_VIRTFS_DEVS 16

#define MNT_TAG_LEN_MAX 128

static char *strnchr(char *s, size_t n, int c);
static int p9_version(struct p9_client *c);
static int p9pdu_vwritef(struct p9_fcall *pdu, int optional, const char *fmt,
                         va_list ap);
static void p9stat_free(struct p9_wstat *s);
int virtio_debug = 0;

typedef struct {
  int ino;
  int linknest;
  grub_disk_t disk;
  int filename_size;
  grub_size_t block_size;
  unsigned long magic;
  struct p9_fid *root_fid;
  struct p9_fid *file_fid;
  int is_mounted;
  struct p9_client *client;
} grub_virtfs_data;

typedef struct {
  unsigned long magic;
  grub_virtfs_data *vfs_data;
  struct vring_virtqueue vq;
  grub_uint16_t bar0;
  struct grub_pci_dma_chunk *ring_chunk;
  void *ring;
  grub_uint32_t ring_pa;
  char mount_tag[MNT_TAG_LEN_MAX];
} virtio_state;

typedef struct {
  virtio_state devstate[MAX_VIRTFS_DEVS]; //disk->data = &devstate[i]
  int nextdevslot;
} dev_states;

dev_states global_devs;

static grub_virtfs_data *grub_virtfs_mount(grub_device_t dev);

static virtio_state *virtio_9p_get_data(const char *mount_tag)
{
  int i;
  for (i = 0; i < global_devs.nextdevslot; i++) {
    if (!grub_strcmp(global_devs.devstate[i].mount_tag, mount_tag))
      return &global_devs.devstate[i];
  }
  return NULL;
}

//return 1 if passed ptr is a valid dev data ptr
static int virtio_9p_check_data(virtio_state * dev_data)
{
  int i;
  for (i = 0; i < global_devs.nextdevslot; i++) {
    if (&global_devs.devstate[i] == dev_data)
      return 1;
  }
  return 0;
}

/* Send buf through virtio device; block on wait and return receieved. */
static unsigned int
virtio_9p_send_buf(virtio_state * vio_data, struct grub_pci_dma_chunk *sendbuf,
                   unsigned int sendlen, struct grub_pci_dma_chunk *recvbuf)
{
  if (vio_data->magic != 0xdeadbeef) {
    grub_printf("something squashed the magic\n");
    while (1) ;
  }
  unsigned int recvlen = 0;
  if (!(recvbuf && sendbuf && (sendlen > 0)))
    return 0;

  struct vring_list desc[] = {
    {
     .addr = (char *)grub_dma_get_phys(sendbuf),
     .length = sendlen,
     },
    {
     .addr = (char *)grub_dma_get_phys(recvbuf),
     .length = PAGE_SIZE,
     },
  };

  if (!vio_data)
    return 0;

  vring_add_buf(&vio_data->vq, desc, 1, 1, (void *)0, 0);
  vring_kick(vio_data->bar0, &(vio_data->vq), 1);

  while (!vring_more_used(&vio_data->vq)) ;

  /* puts recieved buff in phys(recvbuf) */
  vring_get_buf(&vio_data->vq, &recvlen);

  return recvlen;
}

static int NESTED_FUNC_ATTR
grub_virtio_pciinit(grub_pci_device_t dev, grub_pci_id_t pciid)
{
  USED(pciid);
  grub_uint16_t vendID, devID;
  grub_uint16_t num;
  struct vring *vr;
  grub_uint32_t qsize;

  grub_pci_address_t addr = grub_pci_make_address(dev, GRUB_PCI_REG_VENDOR);
  vendID = grub_pci_read(addr);
  addr = grub_pci_make_address(dev, GRUB_PCI_REG_DEVICE);
  devID = grub_pci_read(addr);

  if (!((vendID == 0x1af4) && (devID == 0x1009)))
    return 0;

  if (global_devs.nextdevslot >= MAX_VIRTFS_DEVS)
    return 0;

  virtio_state *devstate = &global_devs.devstate[global_devs.nextdevslot++];

  addr = grub_pci_make_address(dev, GRUB_PCI_REG_ADDRESS_REG0);
  devstate->bar0 = grub_pci_read(addr) & ~1;

  int len = grub_inw(devstate->bar0 + VIRTIO_PCI_CONFIG);
  if (len > MNT_TAG_LEN_MAX)
    len = MNT_TAG_LEN_MAX;

  int i;
  for (i = 0; i < len; i++) {
    devstate->mount_tag[i] =
        grub_inb(devstate->bar0 + VIRTIO_PCI_CONFIG + 2 + i);
  }
  devstate->mount_tag[i] = 0;
  devstate->magic = 0xdeadbeef;
  devstate->vfs_data = NULL;

  /* reset status */
  grub_outb(0, devstate->bar0 + VIRTIO_PCI_STATUS);
  num = grub_inw(devstate->bar0 + VIRTIO_PCI_QUEUE_NUM);

  vr = &(devstate->vq.vring);
  qsize = (vring_size(num) + PAGE_MASK) & ~PAGE_MASK;

  /* allocate memory for dev */
  devstate->ring_chunk = grub_memalign_dma32(PAGE_SIZE, qsize);
  devstate->ring = (void *)grub_dma_get_virt(devstate->ring_chunk);
  grub_memset(devstate->ring, 0, qsize);
  devstate->ring_pa = grub_dma_get_phys(devstate->ring_chunk);

  /* init call based on vp_find_vq virtio-pci.c */
  vring_init(vr, num, (unsigned char *)devstate->ring);

  /* pass dev the location of its new mem */
  grub_outl(devstate->ring_pa >> PAGE_SHIFT,
            devstate->bar0 + VIRTIO_PCI_QUEUE_PFN);

  /* tell device that setup finished */
  grub_outb(VIRTIO_CONFIG_S_DRIVER_OK, devstate->bar0 + VIRTIO_PCI_STATUS);

  return 0;
}

/* end virtio driver */

static char *strnchr(char *s, size_t n, int c)
{
  while ((n--) && s && (*s != '\0')) {
    if (*s == c)
      return s;
    s++;
  }
  return NULL;
}

static inline int p9_qid_valid(struct p9_qid *qid)
{
  return (qid && (qid->type || qid->version || qid->path)) ? 1 : 0;
}

static struct p9_fid *p9_walk(struct p9_fid *oldfid, const char *path,
                              int clone)
{
  size_t n;
  char *p, *s;
  struct p9_client *c;
  struct p9_fcall *pdu;
  struct p9_fid *fid;
  int err;

  if (!oldfid)
    goto err_out;

  n = grub_strlen(path) + 1;

  if (n >= P9_PATH_MAX)
    goto err_out;

  c = oldfid->c;
  pdu = p9pdu_get(c);
  p = s = grub_malloc(n);
  if (p == NULL) {
    grub_error(GRUB_ERR_OUT_OF_MEMORY, "p9_walk: couldn't allocate rdir");
    goto err_out;
  }

  grub_memcpy(p, path, n);

  if (clone) {
    fid = p9_fid_get(c, oldfid->uid);
    if (!fid)
      goto err_str;
  } else {
    fid = oldfid;
  }

  while ((size_t) (s - p) < n) {
    char *t;
    struct p9_qid *wqids;
    short nwqids;
    size_t rem;

    /* we know that the first n chars contain '\0'. */
    while ((*s != '\0') && (*s == '/'))
      s++;

    rem = n - (s - p);
    t = strnchr(s, rem, '/');
    if (t) {
      *t = '\0';
    }

    grub_dprintf("virtfs", "%s: c=%p vfs_data=%p, magic=%lx\n",
                 __FUNCTION__, c, c->vio_data,
                 ((grub_virtfs_data *) c->vio_data)->magic);
    err = p9_rpc(c, pdu, P9_Twalk, "ddT", oldfid->fid, fid->fid, 1, &s);
    if (err) {
      grub_dprintf("virtfs", "walk rpc error\n");
      goto err_rpc;
    }

    err = p9pdu_readf(pdu, c->dotu, "R", &nwqids, &wqids);
    if (err)
      goto err_dump;

    if (nwqids != 1)
      goto err_dump;

    oldfid = fid;
    grub_memcpy(&fid->qid, &wqids[0], sizeof(struct p9_qid));

    if (!t || *s == '\0')
      break;

    s = t + 1;
    p9pdu_reset(pdu);
  }

  grub_free(p);
  pdu = p9pdu_put(pdu);

  return fid;

err_dump:
  grub_dprintf("virtfs", "err_dump\n");
  p9pdu_dump(1, pdu);
err_rpc:
  grub_dprintf("virtfs", "err_rpc\n");
  if (p9_qid_valid(&fid->qid)) {
    p9_clunk(fid);
  } else {
    p9_fid_put(fid);
  }
err_str:
  grub_dprintf("virtfs", "err_str\n");
  grub_free(p);
  pdu = p9pdu_put(pdu);
err_out:
  grub_dprintf("virtfs", "err_out\n");
  return NULL;
}

static struct p9_fid *p9_attach(struct p9_client *c, struct p9_fid *afid,
                                char *uname, unsigned n_uname, char *aname,
                                unsigned uid)
{
  struct p9_fcall *pdu;
  struct p9_fid *fid;
  struct p9_qid qid;
  int err;

  fid = p9_fid_get(c, uid);

  if (!fid)
    goto err_out;
  pdu = p9pdu_get(c);
  err = p9_rpc(c, pdu, P9_Tattach, "ddss?d", fid->fid,
               afid ? afid->fid : P9_NOFID, uname, aname, n_uname);
  if (err)
    goto err_rpc;
  err = p9pdu_readf(pdu, c->dotu, "Q", &qid);
  if (err)
    goto err_dump;
  grub_memcpy(&fid->qid, &qid, sizeof(qid));
  pdu = p9pdu_put(pdu);
  return fid;

err_dump:
  p9pdu_dump(1, pdu);
err_rpc:
  p9pdu_put(pdu);
  p9_fid_put(fid);
err_out:
  return NULL;
}

static int p9_version(struct p9_client *c)
{
  int err;
  struct p9_fcall *pdu;
  unsigned msize;
  char *version = NULL;

  pdu = p9pdu_get(c);
  err = p9_rpc(c, pdu, P9_Tversion, "ds", c->msize,
               c->dotu ? "9P2000.u" : "9P2000");

  if (err)
    goto err_rpc;

  err = p9pdu_readf(pdu, c->dotu, "ds", &msize, &version);
  if (err)
    goto err_dump;

  c->msize = (msize < c->msize) ? msize : c->msize;

  if (!grub_memcmp(version, "9P2000.u", 8))
    c->dotu = 1;
  else if (!grub_memcmp(version, "9P2000", 6))
    c->dotu = 0;
  else
    goto err_dump;

  pdu = p9pdu_put(pdu);

  return 0;

err_dump:
  BUG();
  p9pdu_dump(1, pdu);
err_rpc:
  BUG();
  pdu = p9pdu_put(pdu);
  return -1;
}

static struct p9_client *p9_client_create(grub_device_t dev, int dotu,
                                          size_t msize)
{
  struct p9_client *c;
  int i, err;

  grub_dprintf("virtfs", "client create %d %d\n", dotu, msize);
  c = grub_malloc(sizeof(struct p9_client));
  if (!c) {
    grub_dprintf("virtfs", "couldn't alloc client\n");
    grub_error(GRUB_ERR_OUT_OF_MEMORY, "couldn't allocate client");
    goto err;
  }

  /* Fill in the "common" pieces. */
  c->dotu = dotu;
  c->msize = msize;
  c->fid_nr = P9_START_FID;
  c->vio_data = dev->disk->data;

  c->fid_pool = grub_malloc(sizeof(struct p9_fid) * P9_FD_MAX);
  if (c->fid_pool == NULL) {
    grub_error(GRUB_ERR_OUT_OF_MEMORY, "couldn't allocate fid pool");
    goto err;
  }
  grub_memset(c->fid_pool, 0, sizeof(struct p9_fid) * P9_FD_MAX);

  c->pdu_pool = grub_malloc(sizeof(struct p9_fcall *) * P9_TAG_MAX);
  if (c->pdu_pool == NULL) {
    grub_error(GRUB_ERR_OUT_OF_MEMORY, "couldn't allocate pdu pool");
    goto err;
  }
  grub_memset(c->pdu_pool, 0, sizeof(struct fcall *) * P9_TAG_MAX);

  for (i = 0; i < P9_TAG_MAX; i++)
    c->pdu_pool[i] = p9pdu_create(msize);

  err = p9_version(c);
  if (err)
    goto err;
  return c;

err:
  return NULL;
}

static struct p9_fcall *p9pdu_get(struct p9_client *c)
{
  struct p9_fcall *pdu;
  int tid = 0;                  /* NOTE: tid always 0 because we are single threaded */

  pdu = c->pdu_pool[tid];
  p9pdu_reset(pdu);

  return pdu;
}

static struct p9_fcall *p9pdu_put(struct p9_fcall *pdu)
{
  USED(pdu);
  /* since we always use pdu[0] there is no accounting to update, yet */
  return NULL;
}

static struct p9_fid *p9_fid_get(struct p9_client *c, unsigned uid)
{
  struct p9_fid *fid = NULL;
  int i;

  /* TODO: replace with bitmap & ffz */
  for (i = 0; i < P9_FD_MAX; i++) {
    if (c->fid_pool[i].used == 0) {
      fid = &c->fid_pool[i];
      grub_memset(fid, 0, sizeof(*fid));
      fid->c = c;
      fid->fid = c->fid_nr++;
      fid->uid = uid;
      fid->used = 1;
      fid->mode = -1;
      fid->iounit = 0;
      break;
    }
  }

  return fid;
}

static void p9_fid_put(struct p9_fid *fid)
{
  /* TODO: once we have bitmap clear bitmap */
  grub_memset(fid, 0, sizeof(*fid));
}

static int p9_clunk(struct p9_fid *fid)
{
  struct p9_client *c;
  struct p9_fcall *pdu;
  int err;

  if (!fid)
    goto err_out;

  c = fid->c;
  pdu = p9pdu_get(c);
  err = p9_rpc(c, pdu, P9_Tclunk, "d", fid->fid);

  if (err)
    goto err_rpc;

  pdu = p9pdu_put(pdu);
  p9_fid_put(fid);

  return 0;

err_rpc:
  pdu = p9pdu_put(pdu);
err_out:
  return -1;
}

static int p9_open(struct p9_fid *fid, int mode)
{
  int err;
  struct p9_client *c;
  struct p9_fcall *pdu;
  struct p9_qid qid;
  int iounit;

  if (!fid)
    goto err_out;

  if (fid->mode != -1)
    goto err_out;

  c = fid->c;
  pdu = p9pdu_get(c);
  err = p9_rpc(c, pdu, P9_Topen, "db", fid->fid, mode);

  if (err)
    goto err_rpc;

  err = p9pdu_readf(pdu, c->dotu, "Qd", &qid, &iounit);
  if (err)
    goto err_dump;

  grub_memcpy(&fid->qid, &qid, sizeof(struct p9_qid));
  fid->mode = mode;
  fid->iounit = iounit;
  pdu = p9pdu_put(pdu);

  return 0;

err_dump:
  p9pdu_dump(1, pdu);
err_rpc:
  pdu = p9pdu_put(pdu);
err_out:
  return -1;
}

static struct p9_fcall *p9pdu_create(size_t msize)
{
  struct p9_fcall *pdu;

  pdu = grub_malloc(sizeof(*pdu) + msize);
  if (pdu == NULL) {
    grub_error(GRUB_ERR_OUT_OF_MEMORY, "couldn't allocate pdu");
    BUG();
    return NULL;
  }

  grub_memset(pdu, 0, sizeof(*pdu) + msize);

  pdu->capacity = msize;
  pdu->schunk = grub_memalign_dma32(PAGE_SIZE, PAGE_SIZE);
  pdu->sdata = (unsigned char *)grub_dma_get_virt(pdu->schunk);
  return pdu;
}

static void p9pdu_dump(int way, struct p9_fcall *pdu)
{
  if (virtio_debug == 0)
    return;

  if (way)
    grub_printf("]]]\n");
  else
    grub_printf("[[[\n");

  hexdump(16, (char *)pdu->sdata, pdu->size);
}

static size_t pdu_read(struct p9_fcall *pdu, void *data, size_t size)
{
  size_t len = MIN(pdu->size - pdu->offset, size);
  grub_memcpy(data, &pdu->sdata[pdu->offset], len);
  pdu->offset += len;
  return size - len;
}

static size_t pdu_write(struct p9_fcall *pdu, const void *data, size_t size)
{
  size_t len = MIN(pdu->capacity - pdu->size, size);
  grub_memcpy(&pdu->sdata[pdu->size], data, len);
  pdu->size += len;
  return size - len;
}

/*
	b - char
	w - short
	d - int
	q - long long
	s - string
	S - stat
	Q - qid
	D - data blob (int size followed by void *, results are not freed)
	T - array of strings (short count, followed by strings)
	R - array of qids (short count, followed by qids)
	? - if optional = 1, continue parsing
*/

static int
p9pdu_vreadf(struct p9_fcall *pdu, int optional, const char *fmt, va_list ap)
{
  const char *ptr;
  int errcode = 0;

  for (ptr = fmt; *ptr; ptr++) {
    switch (*ptr) {
    case 'b':
      {
        char *val = va_arg(ap, char *);
        if (pdu_read(pdu, val, sizeof(*val))) {
          errcode = -2;
          break;
        }
      }
      break;
    case 'w':
      {
        short *val = va_arg(ap, short *);
        unsigned short le_val;
        if (pdu_read(pdu, &le_val, sizeof(le_val))) {
          errcode = -2;
          break;
        }
        *val = le16_to_cpu(le_val);
      }
      break;
    case 'd':
      {
        int *val = va_arg(ap, int *);
        unsigned le_val;
        if (pdu_read(pdu, &le_val, sizeof(le_val))) {
          errcode = -2;
          break;
        }
        *val = le32_to_cpu(le_val);
      }
      break;
    case 'q':
      {
        long long *val = va_arg(ap, long long *);
        unsigned long long le_val;
        if (pdu_read(pdu, &le_val, sizeof(le_val))) {
          errcode = -2;
          break;
        }
        *val = le64_to_cpu(le_val);
      }
      break;
    case 's':
      {
        char **sptr = va_arg(ap, char **);
        short len;
        int size;

        errcode = p9pdu_readf(pdu, optional, "w", &len);
        if (errcode)
          break;

        size = MAX(len, 0);

        *sptr = grub_malloc(size + 1);
        if (*sptr == NULL) {
          grub_error(GRUB_ERR_OUT_OF_MEMORY, "couldn't alloc sptr");
          errcode = -2;
          break;
        }
        if (pdu_read(pdu, *sptr, size)) {
          errcode = -2;
          grub_free(*sptr);
          *sptr = NULL;
        } else
          (*sptr)[size] = 0;
      }
      break;
    case 'Q':
      {
        struct p9_qid *qid = va_arg(ap, struct p9_qid *);

        errcode = p9pdu_readf(pdu, optional, "bdq",
                              &qid->type, &qid->version, &qid->path);
      }
      break;
    case 'S':
      {
        struct p9_wstat *stbuf = va_arg(ap, struct p9_wstat *);

        grub_memset(stbuf, 0, sizeof(struct p9_wstat));
        stbuf->n_uid = stbuf->n_gid = stbuf->n_muid = -1;
        errcode =
            p9pdu_readf(pdu, optional,
                        "wwdQdddqssss?sddd",
                        &stbuf->size, &stbuf->type,
                        &stbuf->dev, &stbuf->qid,
                        &stbuf->mode,
                        &stbuf->atime,
                        &stbuf->mtime,
                        &stbuf->length,
                        &stbuf->name, &stbuf->uid,
                        &stbuf->gid, &stbuf->muid,
                        &stbuf->extension,
                        &stbuf->n_uid, &stbuf->n_gid, &stbuf->n_muid);
        /* 
         * Don't free on error, external func will take
         * care of it.
         */
      }
      break;
    case 'D':
      {
        int *count = va_arg(ap, int *);
        void **data = va_arg(ap, void **);

        errcode = p9pdu_readf(pdu, optional, "d", count);
        if (!errcode) {
          *count = MIN((unsigned)*count, pdu->size - pdu->offset);
          *data = &pdu->sdata[pdu->offset];
        }
      }
      break;
    case 'T':
      {
        short *nwname = va_arg(ap, short *);
        char ***wnames = va_arg(ap, char ***);

        errcode = p9pdu_readf(pdu, optional, "w", nwname);
        if (!errcode) {
          *wnames = grub_malloc(sizeof(char *) * *nwname);
          if (!*wnames) {
            grub_error(GRUB_ERR_OUT_OF_MEMORY, "couldn't alloc sptr");
            errcode = -1;
          }
        }

        if (!errcode) {
          int i;

          for (i = 0; i < *nwname; i++) {
            errcode = p9pdu_readf(pdu, optional, "s", &(*wnames)
                                  [i]);
            if (errcode)
              break;
          }
        }

        if (errcode) {
          if (*wnames) {
            int i;

            for (i = 0; i < *nwname; i++)
              grub_free(*wnames[i]);
          }
          grub_free(*wnames);
          *wnames = NULL;
        }
      }
      break;
    case 'R':
      {
        short *nwqid = va_arg(ap, short *);
        struct p9_qid **wqids = va_arg(ap, struct p9_qid **);

        *wqids = NULL;

        errcode = p9pdu_readf(pdu, optional, "w", nwqid);
        if (!errcode) {
          *wqids = grub_malloc(*nwqid * sizeof(struct p9_qid));
          if (*wqids == NULL) {
            grub_error(GRUB_ERR_OUT_OF_MEMORY, "couldn't alloc sptr");
            errcode = -1;
          }
        }

        if (!errcode) {
          int i;

          for (i = 0; i < *nwqid; i++) {
            errcode = p9pdu_readf(pdu, optional, "Q", &(*wqids)
                                  [i]);
            if (errcode)
              break;
          }
        }

        if (errcode) {
          grub_free(*wqids);
          *wqids = NULL;
        }
      }
      break;
    case '?':
      if (!optional)
        return 0;
      break;
    default:
      break;
    }

    if (errcode)
      break;
  }

  return errcode;
}

static int
p9pdu_vwritef(struct p9_fcall *pdu, int optional, const char *fmt, va_list ap)
{
  const char *ptr;
  int errcode = 0;

  for (ptr = fmt; *ptr; ptr++) {
    switch (*ptr) {
    case 'b':
      {
        char val = va_arg(ap, int);
        if (pdu_write(pdu, &val, sizeof(val)))
          errcode = -2;
      }
      break;
    case 'w':
      {
        unsigned short val = cpu_to_le16(va_arg(ap, int));
        if (pdu_write(pdu, &val, sizeof(val)))
          errcode = -2;
      }
      break;
    case 'd':
      {
        unsigned val = cpu_to_le32(va_arg(ap, int));
        if (pdu_write(pdu, &val, sizeof(val)))
          errcode = -2;
      }
      break;
    case 'q':
      {
        unsigned long long val = cpu_to_le64(va_arg(ap, long long));
        if (pdu_write(pdu, &val, sizeof(val)))
          errcode = -2;
      }
      break;
    case 's':
      {
        const char *sptr = va_arg(ap, const char *);
        short len = 0;
        if (sptr)
          len = grub_strlen(sptr);

        errcode = p9pdu_writef(pdu, optional, "w", len);
        if (!errcode && pdu_write(pdu, sptr, len))
          errcode = -2;
      }
      break;
    case 'Q':
      {
        const struct p9_qid *qid = va_arg(ap, const struct p9_qid *);
        errcode =
            p9pdu_writef(pdu, optional, "bdq",
                         qid->type, qid->version, qid->path);
      } break;
    case 'S':
      {
        const struct p9_wstat *stbuf = va_arg(ap, const struct p9_wstat *);
        errcode =
            p9pdu_writef(pdu, optional,
                         "wwdQdddqssss?sddd",
                         stbuf->size, stbuf->type,
                         stbuf->dev, &stbuf->qid,
                         stbuf->mode, stbuf->atime,
                         stbuf->mtime,
                         stbuf->length,
                         stbuf->name, stbuf->uid,
                         stbuf->gid, stbuf->muid,
                         stbuf->extension,
                         stbuf->n_uid, stbuf->n_gid, stbuf->n_muid);
      } break;
    case 'D':
      {
        int count = va_arg(ap, int);
        const void *data = va_arg(ap, const void *);

        errcode = p9pdu_writef(pdu, optional, "d", count);
        if (!errcode && pdu_write(pdu, data, count))
          errcode = -2;
      }
      break;
    case 'T':
      {
        short nwname = va_arg(ap, int);
        const char **wnames = va_arg(ap, const char **);

        errcode = p9pdu_writef(pdu, optional, "w", nwname);
        if (!errcode) {
          int i;

          for (i = 0; i < nwname; i++) {
            errcode = p9pdu_writef(pdu, optional, "s", wnames[i]);
            if (errcode)
              break;
          }
        }
      }
      break;
    case 'R':
      {
        short nwqid = va_arg(ap, int);
        struct p9_qid *wqids = va_arg(ap, struct p9_qid *);

        errcode = p9pdu_writef(pdu, optional, "w", nwqid);
        if (!errcode) {
          int i;

          for (i = 0; i < nwqid; i++) {
            errcode = p9pdu_writef(pdu, optional, "Q", &wqids[i]);
            if (errcode)
              break;
          }
        }
      }
      break;
    case '?':
      if (!optional)
        return 0;
      break;
    default:
      /* BUG(); */
      break;
    }

    if (errcode)
      break;
  }

  return errcode;
}

static int p9pdu_readf(struct p9_fcall *pdu, int optional, const char *fmt, ...)
{
  va_list ap;
  int ret;

  va_start(ap, fmt);
  ret = p9pdu_vreadf(pdu, optional, fmt, ap);
  va_end(ap);

  return ret;
}

static int
p9pdu_writef(struct p9_fcall *pdu, int optional, const char *fmt, ...)
{
  va_list ap;
  int ret;

  va_start(ap, fmt);
  ret = p9pdu_vwritef(pdu, optional, fmt, ap);
  va_end(ap);

  return ret;
}

static int p9pdu_prepare(struct p9_fcall *pdu, short tag, char type)
{
  return p9pdu_writef(pdu, 0, "dbw", 0, type, tag);
}

static int p9pdu_finalize(struct p9_fcall *pdu)
{
  int size = pdu->size;
  int err;

  pdu->size = 0;
  err = p9pdu_writef(pdu, 0, "d", size);
  pdu->size = size;

  p9pdu_dump(0, pdu);

  return err;
}

static void p9pdu_reset(struct p9_fcall *pdu)
{
  pdu->sdata = (unsigned char *)grub_dma_get_virt(pdu->schunk);
  pdu->offset = 0;
  pdu->size = 0;
}

static int
p9_read(struct p9_fid *fid, char *data, unsigned long long offset,
        unsigned count)
{
  int err;
  unsigned iounit;
  struct p9_client *c;
  struct p9_fcall *pdu;
  char *dataptr = NULL;

  if (!fid)
    goto err_out;

  c = fid->c;
  pdu = p9pdu_get(c);
  iounit = p9_iounit(fid, count);
  err = p9_rpc(c, pdu, P9_Tread, "dqd", fid->fid, offset, iounit);

  if (err)
    goto err_rpc;

  err = p9pdu_readf(pdu, c->dotu, "D", &count, &dataptr);
  if (err)
    goto err_dump;

  if (data)
    grub_memcpy(data, dataptr, count);

  pdu = p9pdu_put(pdu);

  return count;

err_dump:
  p9pdu_dump(1, pdu);
err_rpc:
  pdu = p9pdu_put(pdu);
err_out:
  return -1;
}

static int
p9_fid_readn(struct p9_fid *fid, char *data, unsigned long count,
             unsigned long long offset)
{
  int n, total, size;
  n = 0;
  total = 0;
  size = fid->iounit ? fid->iounit : fid->c->msize - P9_IOHDRSZ;
  do {
    n = p9_read(fid, data, offset, count);
    if (n <= 0)
      break;

    if (data)
      data += n;

    offset += n;
    count -= n;
    total += n;
  } while (count > 0 && n == size);

  if (n < 0)
    total = n;

  return total;
}

static int p9_check_errors(struct p9_fcall *pdu, int dotu)
{
  char r_type;
  short r_tag;
  int r_size;
  int err = 0;

  pdu->offset = 0;
  if (pdu->size == 0)
    pdu->size = 7;

  err = p9pdu_readf(pdu, dotu, "dbw", &r_size, &r_type, &r_tag);
  if (err)
    goto out;

  pdu->size = r_size;
  pdu->id = r_type;
  pdu->tag = r_tag;

  if (pdu->id == P9_Rerror) {
    int ecode;
    char *ename;

    err = p9pdu_readf(pdu, dotu, "s?d", &ename, &ecode);
    if (err)
      goto out;
    if (dotu)
      err = -ecode;
  }

out:
  return err;
}

static int p9_tag_get(int type)
{
  int tid = 0;
  return (type != P9_Tversion) ? tid : P9_NOTAG;
}

static int
p9_rpc(struct p9_client *c, struct p9_fcall *pdu, int type, const char *fmt,
       ...)
{
  va_list ap;
  int tag;
  int err;

  tag = p9_tag_get(type);
  p9pdu_prepare(pdu, tag, type);
  va_start(ap, fmt);
  err = p9pdu_vwritef(pdu, c->dotu, fmt, ap);
  if (err) {
    return -1;
  }
  va_end(ap);
  p9pdu_finalize(pdu);

  if (err)
    goto err_out;

  p9pdu_dump(0, pdu);

  grub_dprintf("virtfs", "%s: c=%p vfs_data=%p, magic=%lx\n",
               __FUNCTION__, c, c->vio_data,
               ((grub_virtfs_data *) c->vio_data)->magic);
  err = virtio_9p_send_buf(c->vio_data, pdu->schunk, pdu->size, pdu->schunk);
  pdu->offset = 0;
  if (err < 0)
    goto err_out;
  pdu->size = err;
  p9pdu_dump(1, pdu);

  err = p9_check_errors(pdu, c->dotu);
  if (err)
    goto err_out;

  return 0;

err_out:
  return -1;
}

static int p9_stat(struct p9_fid *fid, struct p9_wstat *buf)
{
  int err;
  struct p9_client *c;
  struct p9_fcall *pdu;
  unsigned short unused;

  if (!fid)
    goto err_out;

  c = fid->c;
  pdu = p9pdu_get(c);
  err = p9_rpc(c, pdu, P9_Tstat, "d", fid->fid);

  if (err)
    goto err_rpc;

  err = p9pdu_readf(pdu, c->dotu, "wS", &unused, buf);
  if (err)
    goto err_dump;

  pdu = p9pdu_put(pdu);

  return 0;

err_dump:
  p9pdu_dump(1, pdu);
err_rpc:
  pdu = p9pdu_put(pdu);
err_out:
  return -1;
}

static int
p9stat_read(char *buf, int len, struct p9_wstat *st, int proto_version)
{
  struct p9_fcall fake_pdu;
  int ret;

  fake_pdu.size = len;
  fake_pdu.capacity = len;
  fake_pdu.sdata = (unsigned char *)buf;
  fake_pdu.offset = 0;

  ret = p9pdu_readf(&fake_pdu, proto_version, "S", st);

  p9pdu_dump(1, &fake_pdu);

  return ret;
}

static void p9stat_init(struct p9_wstat *stbuf)
{
  stbuf->name = NULL;
  stbuf->uid = NULL;
  stbuf->gid = NULL;
  stbuf->muid = NULL;
  stbuf->extension = NULL;
}

static struct p9_wstat *p9stat_alloc(void)
{
  struct p9_wstat *s = grub_malloc(sizeof(struct p9_wstat));
  if (s == NULL) {
    grub_error(GRUB_ERR_OUT_OF_MEMORY, "couldn't allocate stat");
    BUG();
    return NULL;
  }
  grub_dprintf("virtfs-stat", "virtfs stat_alloc\n");
  p9stat_init(s);
  return s;
}

static void p9stat_free(struct p9_wstat *s)
{
  grub_free(s->name);
  grub_free(s->uid);
  grub_free(s->gid);
  grub_free(s->muid);
  grub_free(s->extension);
  grub_free(s);
}

/* Begin Grub Specific FS Code */

static grub_virtfs_data *grub_virtfs_mount(grub_device_t dev)
{
  if (!virtio_9p_check_data(dev->disk->data)) {
    grub_error(GRUB_ERR_UNKNOWN_DEVICE, "can't open device");
    return NULL;
  }

  grub_virtfs_data *vfs_data = ((virtio_state *) dev->disk->data)->vfs_data;

  if (!vfs_data) {
    vfs_data = grub_malloc(sizeof(grub_virtfs_data));
    if (vfs_data == NULL) {
      grub_error(GRUB_ERR_OUT_OF_MEMORY, "couldn't allocate stat");
      BUG();
      return NULL;
    }
    ((virtio_state *) dev->disk->data)->vfs_data = vfs_data;
    vfs_data->is_mounted = 0;
    vfs_data->magic = 0xb00f4ead;
  }

  if (vfs_data->magic != 0xb00f4ead) {
    grub_dprintf("virtfs", "all the magic is gone from the world\n");
    grub_error(GRUB_ERR_BUG, "memory corruption");
    return NULL;
  }

  if (vfs_data->is_mounted == 1)
    return vfs_data;

  vfs_data->client = p9_client_create(dev, 1, P9_MSIZE);
  if (vfs_data->client == 0) {
    grub_dprintf("virtfs", "Failed to create client in virtfs_mount\n");
    grub_error(GRUB_ERR_BAD_FS, "client couldn't connect");
    return NULL;
  }

  vfs_data->root_fid = p9_attach(vfs_data->client, 0, "", 0, "", 0);
  vfs_data->is_mounted = 1;
  return vfs_data;
}

static void *grub_virtfs_walk(struct grub_file *file, const char *pathname)
{
  grub_virtfs_data *vfs_data = grub_virtfs_mount(file->device);
  if (!vfs_data) {
    grub_dprintf("virtfs", "%s: virtfs data is null\n", __FUNCTION__);
    return 0;
  }
  vfs_data->file_fid = p9_walk(vfs_data->root_fid, pathname, 1);
  if (!vfs_data->file_fid) {
    grub_dprintf("virtfs", "%s: data->file_fid is null\n", __FUNCTION__);
    return 0;
  }
  return vfs_data->file_fid;
}

static void *grub_virtfs_walk_fid(struct p9_fid *fid, const char *pathname)
{
  struct p9_fid *t_fid = p9_walk(fid, pathname, 1);
  if (!t_fid) {
    grub_dprintf("virtfs", "There was an error in grub_virtfs_walk_fid\n");
    return 0;
  }
  return t_fid;
}

static grub_err_t grub_virtfs_open(struct grub_file *file, const char *name)
{
  int ret;
  struct p9_wstat *st;

  grub_virtfs_data *vfs_data = grub_virtfs_mount(file->device);
  if (!vfs_data) {
    grub_dprintf("virtfs", "%s: virtfs data is null\n", __FUNCTION__);
    grub_error(GRUB_ERR_BAD_FS, "file system error");
    return -1;
  }

  st = p9stat_alloc();

  vfs_data->file_fid = grub_virtfs_walk(file, name);
  if (!vfs_data->file_fid) {
    grub_dprintf("virtfs", "%s: data->file_fid is null\n", __FUNCTION__);
    grub_error(GRUB_ERR_FILE_NOT_FOUND, "file does not exist");
    p9stat_free(st);
    return -1;
  }

  ret = p9_stat(vfs_data->file_fid, st);
  if (ret < 0) {
    grub_dprintf("virtfs", "fid %d stat failure\n", vfs_data->file_fid->fid);
    p9_clunk(vfs_data->file_fid);
    grub_error(GRUB_ERR_ACCESS_DENIED, "access denied");
    p9stat_free(st);
    return -1;
  }

  ret = p9_open(vfs_data->file_fid, P9_ORDWR);
  if (ret < 0) {
    grub_dprintf("virtfs", "fid %d open failure\n", vfs_data->file_fid->fid);
    p9_clunk(vfs_data->file_fid);
    grub_error(GRUB_ERR_ACCESS_DENIED, "access denied");
    p9stat_free(st);
    return -1;
  }

  file->size = st->length;

  p9stat_free(st);

  return 0;
}

static struct p9_fid *grub_virtfs_open_fid(struct p9_fid *fid, const char *name)
{
  struct p9_fid *t_fid = grub_virtfs_walk_fid(fid, name);
  if (!t_fid) {
    grub_dprintf("virtfs", "open_fid: walk_fid failed\n");
    return NULL;
  }
  if (p9_open(t_fid, P9_ORDWR) < 0) {
    grub_dprintf("virtfs", "open_fid: open failed; file_fid not set\n");
    return NULL;
  }
  return t_fid;
}

static grub_err_t
grub_virtfs_dir(grub_device_t device, const char *path,
                int (*hook) (const char *filename,
                             const struct grub_dirhook_info * info))
{
  int err = 0;
  int bufflen, f_pos;
  struct p9_rdir *rdir;
  struct p9_wstat *st;

  grub_dprintf("virtfs", "virtfs dir opening path=%s\n", path);

  grub_virtfs_data *vfs_data = grub_virtfs_mount(device);
  if (!vfs_data) {
    grub_dprintf("virtfs", "%s: virtfs data is null\n", __FUNCTION__);
    grub_error(GRUB_ERR_BAD_FS, "virtfs_dir: mount failed");
    return -1;
  }

  bufflen = vfs_data->root_fid->c->msize - P9_IOHDRSZ;
  err = f_pos = 0;

  rdir = grub_malloc(sizeof(struct p9_rdir) + bufflen);
  if (rdir == NULL) {
    grub_error(GRUB_ERR_OUT_OF_MEMORY, "virtfs_dir: couldn't allocate rdir");
    return -1;
  }

  rdir->head = rdir->tail = 0;
  rdir->buf = (char *)rdir + sizeof(struct p9_rdir);

  //walk to directory to be dirred
  vfs_data->file_fid = grub_virtfs_open_fid(vfs_data->root_fid, path);
  if (!vfs_data->file_fid) {
    grub_dprintf("virtfs",
                 "%s: open_fid failed to open path=%s\n", __FUNCTION__, path);
    grub_error(GRUB_ERR_FILE_NOT_FOUND, "open failed");
    return -1;
  }

  if (vfs_data->file_fid->qid.type != P9_QTDIR) {
    grub_dprintf("virtfs",
                 "%s: tried to dir file %s of type %d\n", __FUNCTION__, path,
                 vfs_data->file_fid->qid.type);
    grub_error(GRUB_ERR_BAD_FILE_TYPE, "not a directory");
    err = -1;
    goto done;
  }

  while (err == 0) {
    struct grub_dirhook_info *info;
    if (rdir->tail == rdir->head) {
      err = p9_fid_readn(vfs_data->file_fid, rdir->buf, bufflen, f_pos);

      if (err <= 0)
        goto done;

      rdir->head = 0;
      rdir->tail = err;
    }
    while (rdir->head < rdir->tail) {
      st = p9stat_alloc();

      err = p9stat_read(rdir->buf + rdir->head, rdir->tail - rdir->head, st, 1);
      if (err) {
        grub_dprintf("virtfs",
                     "error while read dir data from head to tail, error: %d\n",
                     err);
        grub_error(GRUB_ERR_IO, "virtfs_dir: couldn't parse directory");
        goto done;
      }

      info = grub_malloc(sizeof(info));
      if (info == NULL) {
        grub_error(GRUB_ERR_OUT_OF_MEMORY,
                   "virtfs_dir: couldn't allocate info");
        return -1;
      }
      grub_memset(info, 0, sizeof(info));
      info->mtimeset = 1;
      info->mtime = st->mtime;
      info->case_insensitive = 0;
      info->dir = ((unsigned)st->type & P9_QTDIR);
      hook(st->name, info);
      rdir->head += st->size + 2;
      f_pos += st->size + 2;
      grub_free(info);
      p9stat_free(st);
    }
  }

done:
  p9_clunk(vfs_data->file_fid);
  return err;
}

static grub_ssize_t
grub_virtfs_read(grub_file_t file, char *buf, grub_size_t len)
{
  int ret;

  grub_virtfs_data *vfs_data = grub_virtfs_mount(file->device);
  if (!vfs_data) {
    grub_dprintf("virtfs", "%s: virtfs data is null\n", __FUNCTION__);
    grub_error(GRUB_ERR_BAD_FS, "virtfs_close mount failed");
    return -1;
  }

  grub_dprintf("virtfs",
               "grub_virtfs_read: fid %d offset: %d, size: %d\n",
               vfs_data->file_fid->fid, (int)file->offset, len);

  ret = p9_fid_readn(vfs_data->file_fid, buf, len, file->offset);
  if (ret < 0)
    grub_error(GRUB_ERR_FILE_READ_ERROR, "Virtfs couldn't read file");

  return ret;
}

static
grub_err_t grub_virtfs_close(grub_file_t file)
{
  grub_virtfs_data *vfs_data = grub_virtfs_mount(file->device);
  if (!vfs_data) {
    grub_dprintf("virtfs", "%s: virtfs data is null\n", __FUNCTION__);
    grub_error(GRUB_ERR_BAD_FS, "virtfs_close: mount failed");
    return -1;
  }

  grub_dprintf("virtfs", "entering grub_virtfs_clunk fid=%d\n",
               vfs_data->file_fid->fid);
  return p9_clunk(vfs_data->file_fid);
}

static struct grub_fs grub_virtfs_fs = {
  .name = "virtfsfs",
  .dir = grub_virtfs_dir,
  .open = grub_virtfs_open,
  .read = grub_virtfs_read,
  .close = grub_virtfs_close,
#ifdef GRUB_UTIL
  .reserved_first_sector = 1,
#endif
  .next = 0
};

/* Virtio disk dev */
static int grub_virtdisk_iterate(int (*hook) (const char *name))
{
  int i;
  for (i = 0; i < global_devs.nextdevslot; i++) {
    grub_dprintf("virtfs", "%s: mount_tag=%s\n", __FUNCTION__,
                 global_devs.devstate[i].mount_tag);
    if (hook(global_devs.devstate[i].mount_tag))
      return 1;
  }
  return 0;
}

static grub_err_t grub_virtdisk_open(const char *name, grub_disk_t disk)
{
  disk->total_sectors = 2048;

  virtio_state *dev_data = virtio_9p_get_data(name);
  if (!dev_data)
    return grub_error(GRUB_ERR_UNKNOWN_DEVICE, "can't open device");

  if (dev_data->magic != 0xdeadbeef) {
    grub_printf("something squashed the magic\n");
    grub_sleep(1);
  }
  disk->id = GRUB_DISK_DEVICE_VIRTIO_ID;
  disk->data = dev_data;
  return GRUB_ERR_NONE;
}

static void grub_virtdisk_close(grub_disk_t disk)
{
  USED(disk);
}

static grub_err_t
grub_virtdisk_read(grub_disk_t disk, grub_disk_addr_t sector,
                   grub_size_t size, char *buf)
{
  grub_dprintf("virtio", "%s\n", __FUNCTION__);
  USED(disk);
  USED(sector);
  grub_memset(buf, 0, size * 512);
  return GRUB_ERR_NONE;
}

static grub_err_t
grub_virtdisk_write(grub_disk_t disk,
                    grub_disk_addr_t sector, grub_size_t size, const char *buf)
{
  grub_dprintf("virtio", "%s\n", __FUNCTION__);
  USED(disk);
  USED(sector);
  USED(size);
  USED(buf);
  return GRUB_ERR_NONE;
}

static struct grub_disk_dev grub_virtdisk_dev = {
  .name = "virtdisk",
  .id = GRUB_DISK_DEVICE_VIRTIO_ID,
  .iterate = grub_virtdisk_iterate,
  .open = grub_virtdisk_open,
  .close = grub_virtdisk_close,
  .read = grub_virtdisk_read,
  .write = grub_virtdisk_write,
  .next = 0
};

/* End virtio disk dev */

GRUB_MOD_INIT(virtfs)
{
  global_devs.nextdevslot = 0;
  grub_pci_iterate(grub_virtio_pciinit);  //initialize global_devs.devstate
  grub_disk_dev_register(&grub_virtdisk_dev);
  grub_fs_register(&grub_virtfs_fs);
}

GRUB_MOD_FINI(virtfs)
{
  grub_disk_dev_unregister(&grub_virtdisk_dev);
  grub_fs_unregister(&grub_virtfs_fs);
}
