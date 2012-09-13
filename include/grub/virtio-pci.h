#ifndef _VIRTIO_PCI_H_
# define _VIRTIO_PCI_H_

#include <grub/virtio-ring.h> //queue
#include <grub/cpu/io.h> //in/outl

/* A 32-bit r/o bitmask of the features supported by the host */
#define VIRTIO_PCI_HOST_FEATURES        0

/* A 32-bit r/w bitmask of features activated by the guest */
#define VIRTIO_PCI_GUEST_FEATURES       4

/* A 32-bit r/w PFN for the currently selected queue */
#define VIRTIO_PCI_QUEUE_PFN            8

/* A 16-bit r/o queue size for the currently selected queue */
#define VIRTIO_PCI_QUEUE_NUM            12

/* A 16-bit r/w queue selector */
#define VIRTIO_PCI_QUEUE_SEL            14

/* A 16-bit r/w queue notifier */
#define VIRTIO_PCI_QUEUE_NOTIFY         16

/* An 8-bit device status register.  */
#define VIRTIO_PCI_STATUS               18

/* An 8-bit r/o interrupt status register.  Reading the value will return the
 * current contents of the ISR and will also clear it.  This is effectively
 * a read-and-acknowledge. */
#define VIRTIO_PCI_ISR                  19

/* The bit of the ISR which indicates a device configuration change. */
#define VIRTIO_PCI_ISR_CONFIG           0x2

/* The remaining space is defined by each driver as the per-driver
 * configuration space */
#define VIRTIO_PCI_CONFIG               20

/* Virtio ABI version, this must match exactly */
#define VIRTIO_PCI_ABI_VERSION          0

static inline grub_uint32_t vp_get_features(unsigned int ioaddr)
{
   return grub_inl(ioaddr + VIRTIO_PCI_HOST_FEATURES);
}

static inline void vp_set_features(unsigned int ioaddr, grub_uint32_t features)
{
        grub_outl(features, ioaddr + VIRTIO_PCI_GUEST_FEATURES);
}

static inline void vp_get(unsigned int ioaddr, unsigned offset,
                     void *buf, unsigned len)
{
   grub_uint8_t *ptr = buf;
   unsigned i;

   for (i = 0; i < len; i++)
           ptr[i] = grub_inb(ioaddr + VIRTIO_PCI_CONFIG + offset + i);
}

static inline grub_uint8_t vp_get_status(unsigned int ioaddr)
{
   return grub_inb(ioaddr + VIRTIO_PCI_STATUS);
}

static inline void vp_set_status(unsigned int ioaddr, grub_uint8_t status)
{
   if (status == 0)        /* reset */
           return;
   grub_outb(status, ioaddr + VIRTIO_PCI_STATUS);
}

static inline grub_uint8_t vp_get_isr(unsigned int ioaddr)
{
   return grub_inb(ioaddr + VIRTIO_PCI_ISR);
}

static inline void vp_reset(unsigned int ioaddr)
{
   grub_outb(0, ioaddr + VIRTIO_PCI_STATUS);
   (void)grub_inb(ioaddr + VIRTIO_PCI_ISR);
}

static inline void vp_notify(unsigned int ioaddr, int queue_index)
{
   grub_outw(queue_index, ioaddr + VIRTIO_PCI_QUEUE_NOTIFY);
}

static inline void vp_del_vq(unsigned int ioaddr, int queue_index)
{
   /* select the queue */

   grub_outw(queue_index, ioaddr + VIRTIO_PCI_QUEUE_SEL);

   /* deactivate the queue */

   grub_outl(0, ioaddr + VIRTIO_PCI_QUEUE_PFN);
}

#endif /* _VIRTIO_PCI_H_ */
