/*
 * net/9p/protocol.h
 *
 * 9P Protocol Support Code
 *
 *  Copyright (C) 2008 by Eric Van Hensbergen  <ericvanhensbergen@us.ibm.com>
 *
 *  Base on code from Anthony Liguori <aliguori@us.ibm.com>
 *  Copyright (C) 2008 by IBM, Corp.
 *
 */

#ifndef __9p_protocol_h__
#define __9p_protocol_h__

#include <stdarg.h>

/* 9p message types */
enum {
  P9_Tfirst = 100,
  P9_Tversion = 100,
  P9_Rversion,
  P9_Tauth = 102,
  P9_Rauth,
  P9_Tattach = 104,
  P9_Rattach,
  P9_Terror = 106,
  P9_Rerror,
  P9_Tflush = 108,
  P9_Rflush,
  P9_Twalk = 110,
  P9_Rwalk,
  P9_Topen = 112,
  P9_Ropen,
  P9_Tcreate = 114,
  P9_Rcreate,
  P9_Tread = 116,
  P9_Rread,
  P9_Twrite = 118,
  P9_Rwrite,
  P9_Tclunk = 120,
  P9_Rclunk,
  P9_Tremove = 122,
  P9_Rremove,
  P9_Tstat = 124,
  P9_Rstat,
  P9_Twstat = 126,
  P9_Rwstat,
  P9_Rlast
};

/* container for 9p RPC transactions. */
struct p9_fcall {
  unsigned int size;
  unsigned char id;
  unsigned short tag;

  size_t offset;
  size_t capacity;
  struct grub_pci_dma_chunk *schunk;
  unsigned char *sdata;
};

/******************************************************************************/

static struct p9_fcall *p9pdu_create(size_t msize);

#if 0
static void p9pdu_destroy(struct p9_fcall *pdu);
static void *p9pdu_malloc(struct p9_fcall *pdu, size_t sz);
static void p9pdu_free(struct p9_fcall *pdu, void *p);
static unsigned p9pdu_heap(struct p9_fcall *pdu);
#endif

static int p9pdu_writef(struct p9_fcall *pdu, int optional, const char *fmt,
                        ...);
static int p9pdu_readf(struct p9_fcall *pdu, int optional, const char *fmt,
                       ...);
static int p9pdu_prepare(struct p9_fcall *pdu, short tag, char type);
static int p9pdu_finalize(struct p9_fcall *pdu);
static void p9pdu_dump(int, struct p9_fcall *);
static void p9pdu_reset(struct p9_fcall *pdu);
static int p9stat_read(char *buf, int len, struct p9_wstat *st,
                       int proto_version);
#endif
