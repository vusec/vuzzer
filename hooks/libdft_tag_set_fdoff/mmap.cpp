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
void post_mmap2_hook<libdft_tag_set_fdoff>(syscall_ctx_t *ctx) {
	/* not successful; optimized branch */
	if (unlikely(_ADDR == (ADDRINT)-1)) {
		LOG("ERROR " _CALL_LOG_STR + " (" + strerror(errno) + ")\n");
		return;
	}

	if (_FD >= 0 && fdset.find(_FD) != fdset.end()) {
		LOG("OK    " _CALL_LOG_STR + "\n");

		/* set tags on mapped area */
		const ufd_t ufd = ufdmap.get(_FD);
		size_t i = 0;

		while(i<_LENGTH) {
			tag_t ts {{ufd, _FD_OFFSET+i}};
			tag_t ts_prev = tagmap_getb(_ADDR+i);

			tagmap_setb_with_tag(_ADDR+i, ts);

			LOG( "mmap:tags[" + StringFromAddrint(_ADDR+i) + "] : " +
				tag_sprint(ts_prev) + " -> " +
				tag_sprint(tagmap_getb(_ADDR+i)) + "\n"
			);
			i++;
		}
	}
	else {
		/* log mapping if it is anonymous */
		if (_FD == -1) LOG("OK    " _CALL_LOG_STR + "\n");

		/* clear tags on mapped area */
		size_t i = 0;
		while(i<_LENGTH) { tagmap_clrb(_ADDR+i); i++; }
	}
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
void post_munmap_hook<libdft_tag_set_fdoff>(syscall_ctx_t *ctx) {
	/* not successful; optimized branch */
	if (unlikely(_RET_STATUS < 0)) {
		LOG("ERROR " _CALL_LOG_STR + " (" + strerror(errno) + ")\n");
		return;
	}

	LOG("OK    " _CALL_LOG_STR + "\n");
	for(size_t i=0; i<_LENGTH; i++) tagmap_clrb(_ADDR+i);
}
#define UNDEF_SYSCALL_MUNMAP
#include "hooks/syscall_args.h"

/* vim: set noet ts=4 sts=4 sw=4 ai : */
