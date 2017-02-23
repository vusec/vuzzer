#include "hooks/hooks.H"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "libdft_api.h"
#include "tagmap.h"
#include "pin.H"

#include "dtracker.H"
#include "osutils.H"


// TODO: Consider hooking mprotect(2).

/*
 * mmap2(2) handler (taint-source)
 *
 * Signature: void *mmap2(void *addr, size_t length, int prot, int flags, int fd, off_t pgoffset);
 *                            ARG0        ARG1         ARG2      ARG3       ARG4      ARG5 
 *
 * TODO: Don't forget to also create hooks for munmap(), mremap().
 */
#define DEF_SYSCALL_MMAP2
#include "hooks/syscall_args.h"
template<>
void post_mmap2_hook<libdft_tag_bvector>(syscall_ctx_t *ctx) {
	LOG("mmap not implemented\n");
}
#define UNDEF_SYSCALL_MMAP2
#include "hooks/syscall_args.h"

/*
 * munmap(2) handler
 *
 * Signature: int munmap(void *addr, size_t length);
 *
 */
#define DEF_SYSCALL_MUNMAP
#include "hooks/syscall_args.h"
template<>
void post_munmap_hook<libdft_tag_bvector>(syscall_ctx_t *ctx) {
	LOG("munmap not implemented\n");
}
#define UNDEF_SYSCALL_MUNMAP
#include "hooks/syscall_args.h"

/* vim: set noet ts=4 sts=4 sw=4 ai : */
