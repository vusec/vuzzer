#include "hooks/hooks.H"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "libdft_api.h"
#include "tagmap.h"
#include "pin.H"

#include "provlog.H"
#include "dtracker.H"
#include "osutils.H"

/* tracks whether path existed before the execution of syscall */
static struct {
	std::string pathname;
	int existed_before_syscall;
} exist_status;

/*
 * open(2)/creat(2) handlers
 *
 * Signatures:
 * int open(const char *pathname, int flags);
 * int open(const char *pathname, int flags, mode_t mode);
 * int creat(const char *pathname, mode_t mode);
 */
#define DEF_SYSCALL_OPEN
#include "hooks/syscall_args.h"
template<>
void pre_open_hook<libdft_tag_bitset>(syscall_ctx_t *ctx) {
	/* Check the status of the pathname we are about to open/create. */
	exist_status.pathname = std::string(_PATHNAME);
	exist_status.existed_before_syscall = path_exists(exist_status.pathname);
	//std::cerr << exist_status.pathname << std::endl;
	//std::cerr << exist_status.existed_before_syscall << std::endl;
}
template<>
void post_open_hook<libdft_tag_bitset>(syscall_ctx_t *ctx) {
	/* not successful; optimized branch */
	if (unlikely(_FD < 0)) {
		LOG("ERROR " _CALL_LOG_STR + " (" + strerror(errno) + ")\n");
		return;
	}

	/* Resolve fd to full pathname. Use this instead of syscall argument. */
	const std::string fdn = fdname(_FD);

	if ( !in_dtracker_whitelist(fdn) && !path_isdir(fdn) ) {
		const PROVLOG::ufd_t ufd = PROVLOG::ufdmap[_FD];
		fdset.insert(_FD);

		int created = (
			exist_status.existed_before_syscall != 1 &&
			(_FLAGS & O_CREAT) && 
			exist_status.pathname == std::string(_PATHNAME)
		);

		LOG("OK    " _CALL_LOG_STR + "\n");
		LOG("INFO  mapped fd" + decstr(_FD) + ":ufd" + decstr(ufd) + "\n");
		PROVLOG::open(ufd, fdn, _FLAGS, created);
	}
	else {
		LOG("INFO  ignoring fd" + decstr(_FD) + " (" + fdn + ")\n");
	}

	/* reset the exist_status */
	exist_status.existed_before_syscall = 0;
}
#define UNDEF_SYSCALL_OPEN
#include "hooks/syscall_args.h"

/*
 * close(2) handler - updates watched fds
 *
 * Signature: int close(int fd);
 */
#define DEF_SYSCALL_CLOSE
#include "hooks/syscall_args.h"
template<>
void post_close_hook<libdft_tag_bitset>(syscall_ctx_t *ctx) {
	/* not successful; optimized branch */
	if (unlikely(_RET_STATUS < 0)) {
		LOG("ERROR " _CALL_LOG_STR + " (" + strerror(errno) + ")\n");
		return;
	}

	LOG("OK    " _CALL_LOG_STR + "\n");

	std::set<int>::iterator it = fdset.find(_FD);
	if (it == fdset.end()) return;
	const PROVLOG::ufd_t ufd = PROVLOG::ufdmap[_FD];


	fdset.erase(it);
	PROVLOG::ufdmap.del(_FD);
	if (IS_STDFD(_FD)) stdcount[_FD] = 0;

	LOG("INFO  removed mapping fd" + decstr(_FD) + ":ufd" + decstr(ufd) + "\n");
	PROVLOG::close(ufd);
}
#define UNDEF_SYSCALL_CLOSE
#include "hooks/syscall_args.h"

/* vim: set noet ts=4 sts=4 sw=4 ai : */
