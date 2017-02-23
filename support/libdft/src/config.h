#ifndef __CONFIG_H__
#define __CONFIG_H__

// Enable custom taint tags unless default tags are explicitly requested.
#if defined(LIBDFT_DEFAULT_TAG_TYPE)
#undef LIBDFT_TAG_TYPE
#undef USE_CUSTOM_TAG
#elif !defined(LIBDFT_TAG_TYPE)
#define LIBDFT_TAG_TYPE libdft_tag_set_uint32
#endif

#ifdef LIBDFT_TAG_TYPE
#define USE_CUSTOM_TAG
#include "tag_traits.h"

// Currently available tag types:
//		libdft_tag_uint8
//		libdft_tag_set_uint32
//		libdft_tag_set_fdoff
//		libdft_tag_bitset
typedef LIBDFT_TAG_TYPE tag_t;
#endif

#endif /* __CONFIG_H__ */

