/* client.h - internal structures & interfaces.
 */

#ifndef __9p_client_h__
#define __9p_client_h__

#include <stdarg.h>
#include <9p/9p.h>

#define P9_NOTAG        (unsigned short)(~0)
#define P9_NOFID        (unsigned)(~0)
#define P9_IOHDRSZ	24

struct p9_fcall;

struct p9_client {
  size_t msize;
  int dotu;
  int fid_nr;
  void *vio_data;
  struct p9_fid *fid_pool;
  struct p9_fcall **pdu_pool;
};

struct p9_fid {
  unsigned fid;
  unsigned uid;
  unsigned used;
  int mode;
  unsigned iounit;
  char pad[sizeof(void *) - sizeof(unsigned)];
  struct p9_client *c;
  struct p9_qid qid;
};

/******************************************************************************/

static struct p9_fcall *p9pdu_get(struct p9_client *c);
static struct p9_fcall *p9pdu_put(struct p9_fcall *pdu);

static struct p9_fid *p9_fid_get(struct p9_client *c, unsigned uid);
static void p9_fid_put(struct p9_fid *fid);

static int p9_rpc(struct p9_client *c, struct p9_fcall *pdu, int type,
                  const char *fmt, ...);
static int
p9_fid_readn(struct p9_fid *fid, char *data, unsigned long count,
             unsigned long long offset);
/******************************************************************************/

static inline unsigned p9_iounit(struct p9_fid *fid, unsigned count)
{
  struct p9_client *c = fid->c;
  unsigned iounit = fid->iounit;

  if (!iounit || iounit > c->msize - P9_IOHDRSZ)
    iounit = c->msize - P9_IOHDRSZ;

  if (count < iounit)
    iounit = count;

  return iounit;
}

#endif
