#ifndef _VIRTIO_RING_H_
#define _VIRTIO_RING_H_

#include <grub/types.h>

#define PAGE_SHIFT (12)
#define PAGE_SIZE  (1<<PAGE_SHIFT)
#define PAGE_MASK  (PAGE_SIZE-1)

/* Status byte for guest to report progress, and synchronize features. */
/* We have seen device and processed generic fields (VIRTIO_CONFIG_F_VIRTIO) */
#define VIRTIO_CONFIG_S_ACKNOWLEDGE     1
/* We have found a driver for the device. */
#define VIRTIO_CONFIG_S_DRIVER          2
/* Driver has used its parts of the config, and is happy */
#define VIRTIO_CONFIG_S_DRIVER_OK       4
/* We've given up on this device. */
#define VIRTIO_CONFIG_S_FAILED          0x80

#define MAX_QUEUE_NUM      (256)

#define VRING_DESC_F_NEXT  1
#define VRING_DESC_F_WRITE 2

#define VRING_AVAIL_F_NO_INTERRUPT 1

#define VRING_USED_F_NO_NOTIFY     1

struct vring_desc
{
   grub_uint64_t addr;
   grub_uint32_t len;
   grub_uint16_t flags;
   grub_uint16_t next;
};

struct vring_avail
{
   grub_uint16_t flags;
   grub_uint16_t idx;
   grub_uint16_t ring[0];
};

struct vring_used_elem
{
   grub_uint32_t id;
   grub_uint32_t len;
};

struct vring_used
{
   grub_uint16_t flags;
   grub_uint16_t idx;
   struct vring_used_elem ring[];
};

struct vring {
   unsigned int num;
   struct vring_desc *desc;
   struct vring_avail *avail;
   struct vring_used *used;
};

#define vring_size(num) \
   (((((sizeof(struct vring_desc) * num) + \
      (sizeof(struct vring_avail) + sizeof(grub_uint16_t) * num)) \
         + PAGE_MASK) & ~PAGE_MASK) + \
         (sizeof(struct vring_used) + sizeof(struct vring_used_elem) * num))

typedef unsigned char virtio_queue_t[PAGE_MASK + vring_size(MAX_QUEUE_NUM)];

struct vring_virtqueue {
   virtio_queue_t queue;
   struct vring vring;
   grub_uint16_t free_head;
   grub_uint16_t last_used_idx;
   void *vdata[MAX_QUEUE_NUM];
   /* PCI */
   int queue_index;
};

struct vring_list {
  char *addr;
  unsigned int length;
};

//ident in grub
unsigned long virt_to_phys(unsigned long va);
unsigned long phys_to_virt(unsigned long pa); 

#include <grub/misc.h>
static inline void vring_init(struct vring *vr,
                         unsigned int num, unsigned char *queue)
{
   vr->desc = (struct vring_desc *)queue;
   vr->avail = (struct vring_avail *)&vr->desc[num];

   unsigned long used = (unsigned long)&vr->avail->ring[num];
   used = (used + PAGE_MASK) & ~PAGE_MASK;
   vr->used = (struct vring_used *)used;
   vr->num = num;

   unsigned int i;
   for (i = 0; i < num - 1; i++)
           vr->desc[i].next = i + 1;
   vr->desc[i].next = 0;
}

static inline void vring_enable_cb(struct vring_virtqueue *vq)
{
   vq->vring.avail->flags &= ~VRING_AVAIL_F_NO_INTERRUPT;
}

static inline void vring_disable_cb(struct vring_virtqueue *vq)
{
   vq->vring.avail->flags |= VRING_AVAIL_F_NO_INTERRUPT;
}


/*
 * vring_more_used
 *
 * is there some used buffers ?
 *
 */

static inline int vring_more_used(struct vring_virtqueue *vq)
{
   //wmb();  
   return vq->last_used_idx != vq->vring.used->idx;
}

void vring_detach(struct vring_virtqueue *vq, unsigned int head);
void *vring_get_buf(struct vring_virtqueue *vq, unsigned int *len);
void vring_add_buf(struct vring_virtqueue *vq, struct vring_list list[],
                   unsigned int out, unsigned int in,
                   void *index, int num_added);
void vring_kick(unsigned int ioaddr, struct vring_virtqueue *vq, int num_added);

#endif /* _VIRTIO_RING_H_ */
