#ifndef __ENDIAN_H__
#define __ENDIAN_H__

//#include <types.h>

#ifdef _BIG_ENDIAN
#ifndef __BIG_ENDIAN__
#define __BIG_ENDIAN__
#endif
#endif

#ifdef _LITTLE_ENDIAN
#ifndef __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN__
#endif
#endif

#if !(defined(__BIG_ENDIAN__) || defined(__LITTLE_ENDIAN__))
//# error "Compiler does not claim endian"
#endif
/* linuxy types */
typedef unsigned long ulong;

/* rhypie types */
typedef unsigned long long uval64;
typedef signed long long sval64;

#define __pad_for_64 char _pad[sizeof (ulong) - sizeof (unsigned)]
#define __pad_for_32 char _pad[sizeof (uval64) - sizeof (ulong)]

typedef struct _uval128 {
  uval64 _uval128_hi;
  uval64 _uval128_lo;
} uval128 __attribute__ ((aligned(16)));
static inline unsigned short swab16(unsigned short h)
{
  unsigned short r = 0;

  r |= (h & 0x00ffU) << 8;
  r |= (h & 0xff00U) >> 8;

  return r;
}

static inline unsigned swab32(unsigned w)
{
  unsigned r = 0;

  r |= (w & 0x000000ffU) << 24;
  r |= (w & 0x0000ff00U) << 8;
  r |= (w & 0x00ff0000U) >> 8;
  r |= (w & 0xff000000U) >> 24;

  return r;

}

static inline uval64 swab64(uval64 d)
{
  uval64 r = 0;

  r |= (d & 0x00000000000000ffULL) << 56;
  r |= (d & 0x000000000000ff00ULL) << 40;
  r |= (d & 0x0000000000ff0000ULL) << 24;
  r |= (d & 0x00000000ff000000ULL) << 8;
  r |= (d & 0x000000ff00000000ULL) >> 8;
  r |= (d & 0x0000ff0000000000ULL) >> 24;
  r |= (d & 0x00ff000000000000ULL) >> 40;
  r |= (d & 0xff00000000000000ULL) >> 56;

  return r;
}

#define __LITTLE_ENDIAN__
#ifdef __LITTLE_ENDIAN__
#define cpu_to_be16(x) swab16(x)
#define be16_to_cpu(x) swab16(x)
#define cpu_to_be32(x) swab32(x)
#define be32_to_cpu(x) swab32(x)
#define cpu_to_be64(x) swab64(x)
#define be64_to_cpu(x) swab64(x)
#define cpu_to_le16(x) (x)
#define le16_to_cpu(x) (x)
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#define cpu_to_le64(x) (x)
#define le64_to_cpu(x) (x)
#else
#define cpu_to_le16(x) swab16(x)
#define le16_to_cpu(x) swab16(x)
#define cpu_to_le32(x) swab32(x)
#define le32_to_cpu(x) swab32(x)
#define cpu_to_le64(x) swab64(x)
#define le64_to_cpu(x) swab64(x)
#define cpu_to_be16(x) (x)
#define be16_to_cpu(x) (x)
#define cpu_to_be32(x) (x)
#define be32_to_cpu(x) (x)
#define cpu_to_be64(x) (x)
#define be64_to_cpu(x) (x)
#endif

#define swabl(x) swab32(x)

extern void *le_remap(void *addr);
#endif /* __ENDIAN_H__ */
