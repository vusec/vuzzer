/*-
 * Copyright (c) 2010, 2011, 2012, 2013, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * 05/28/2011:
 * 	the size of the bitmap was reverted back to 512MB;
 * 	the vsyscall mechanism results into accessing
 * 	addresses above PAGE_OFFSET (i.e., 0xc0000000)
 */

#ifndef __TAGMAP_H__
#define __TAGMAP_H__

#include "pin.H"
#include "config.h"


#ifndef USE_CUSTOM_TAG
/*
 * the bitmap size in bytes
 *
 * we assign one bit for every addressable
 * byte of the virtual memory; assuming a
 * 32-bit virtual address space, the bitmap
 * size should be 512 MB. However, in most
 * cases the upper 1G is mapped to the
 * kernel, so we only need 384 MB -- when
 * a 2G/2G, or 1G/3G split is used, we need
 * even less bytes for the bitmap (i.e.,
 * 256 MB, or 128 MB respectively).
 */
/* #define BITMAP_SZ	384*1024*1024 */
#define BITMAP_SZ	512*1024*1024

#define BYTE_MASK	0x01U		/* byte mask; 1 bit */
#define WORD_MASK	0x0003U		/* word mask; 2 sequential bits */
#define LONG_MASK	0x000FU		/* long mask; 4 sequential bits */
#define QUAD_MASK	0x00FFU		/* quad mask; 8 sequential bits */
#define _3BYTE_MASK	0x0007U		/* 3 bytes mask; 3 sequential bits */
#define _5BYTE_MASK	0x001FU		/* 5 bytes mask; 5 sequential bits */
#define _6BYTE_MASK	0x003FU		/* 6 bytes mask; 6 sequential bits */
#define _7BYTE_MASK	0x007FU		/* 7 bytes mask; 7 sequential bits */

/* given a virtual address estimate the byte offset on the bitmap */
#define VIRT2BYTE(addr)	((addr) >> 3)

/* given a virtual address estimate the bit offset on the bitmap */
#define VIRT2BIT(addr)	((addr) & 0x00000007U)

#define ALIGN_OFF_MAX	8		/* max alignment offset */
#define ASSERT_FAST	32		/* used in comparisons  */

#else
#include "tagmap_custom.h"
#endif


/* common tagmap API */
int				tagmap_alloc(void);
void				tagmap_free(void);
void	PIN_FAST_ANALYSIS_CALL	tagmap_setb(size_t);
void	PIN_FAST_ANALYSIS_CALL	tagmap_setw(size_t);
void	PIN_FAST_ANALYSIS_CALL	tagmap_setl(size_t);
void	PIN_FAST_ANALYSIS_CALL	tagmap_clrb(size_t);
void	PIN_FAST_ANALYSIS_CALL	tagmap_clrw(size_t);
void	PIN_FAST_ANALYSIS_CALL	tagmap_clrl(size_t);
void				tagmap_clear_all(void);
void				tagmap_taint_all(void);
void				tagmap_setn(size_t, size_t);
void				tagmap_clrn(size_t, size_t);

/* implementation-specific tagmap API */
#ifndef USE_CUSTOM_TAG
size_t				tagmap_getb(size_t);
size_t	PIN_FAST_ANALYSIS_CALL	tagmap_getw(size_t);
size_t	PIN_FAST_ANALYSIS_CALL	tagmap_getl(size_t);
size_t				tagmap_issetn(size_t, size_t);
#else
tag_t				tagmap_getb(size_t);
tag_t				tagmap_getw(size_t);
tag_t				tagmap_getl(size_t);
void	PIN_FAST_ANALYSIS_CALL	tagmap_setb_with_tag(size_t, tag_t const &);
tag_t const *			tagmap_getb_as_ptr(size_t);
#endif

#endif /* __TAGMAP_H__ */

/* vim: set noet ts=8 sts=8 : */
