#include "hooks/hooks.H"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <bm/bm.h>

#include "libdft_api.h"
#include "tagmap.h"
#include "pin.H"

#include "provlog.H"
#include "dtracker.H"
#include "osutils.H"


/*
 * open(2)/creat(2) handlers
 *
 * Signatures:
 * int open(const char *pathname, int flags);
 * int open(const char *pathname, int flags, mode_t mode);
 * int creat(const char *pathname, mode_t mode);
 */
#define DEF_SYSCALL_DUP2
#include "hooks/syscall_args.h"
template<>
void post_dup2_hook<libdft_tag_ewah>(syscall_ctx_t *ctx) {
	/* not successful; optimized branch */
	if (unlikely(_RET_FD < 0)) {
		LOG("ERROR " _CALL_LOG_STR + " (" + strerror(errno) + ")\n");
		return;
	}

	/* Resolve fd to full pathname. Use this instead of syscall argument. */
	const int ret_fd = _RET_FD;
	const int old_fd = _OLD_FD;

        LOG("OK    " _CALL_LOG_STR + "\n");
        if (fdset.find(old_fd) != fdset.end()) {
		fdset.insert(ret_fd);
	}else {
		LOG("INFO  ignoring fd " + decstr(_RET_FD) + "\n");
	}

	/* reset the exist_status */
}
#define UNDEF_SYSCALL_DUP2
#include "hooks/syscall_args.h"

/* vim: set noet ts=4 sts=4 sw=4 ai : */
