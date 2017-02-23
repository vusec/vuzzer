#ifndef __HOOKS_H__
#define __HOOKS_H__
/*
 * Syscall Hooks. Each hook must be specialized for each supported tag type.
 */

#include "libdft_api.h"


/* dtracker_openclose.cpp */
template<typename TagType> void pre_open_hook(syscall_ctx_t *ctx);
template<typename TagType> void post_open_hook(syscall_ctx_t *ctx);
template<typename TagType> void post_close_hook(syscall_ctx_t *ctx);

/* dtracker_read.cpp */
template<typename TagType> void post_read_hook(syscall_ctx_t *ctx);
template<typename TagType> void post_readv_hook(syscall_ctx_t *ctx);
template<typename TagType> void post_pread_hook(syscall_ctx_t *ctx);

/* dtracker_write.cpp */
template<typename TagType> void post_write_hook(syscall_ctx_t *ctx);
template<typename TagType> void post_writev_hook(syscall_ctx_t *ctx);

/* dtracker_mmap.cpp */
template<typename TagType> void post_mmap2_hook(syscall_ctx_t *ctx);
template<typename TagType> void post_munmap_hook(syscall_ctx_t *ctx);
template<typename TagType> void post_mremap_hook(syscall_ctx_t *ctx);

/* dtracker_dup.cpp */
template<typename TagType> void post_dup2_hook(syscall_ctx_t *ctx);
#endif

/* vim: set noet ts=4 sts=4 sw=4 ai : */
