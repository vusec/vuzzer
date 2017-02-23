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

/*
 * read(2) handler (taint-source)
 *
 * Signature: ssize_t read(int fd, void *buf, size_t count);
 */
template<>
void post_read_hook<libdft_tag_bitset>(syscall_ctx_t *ctx) {
	/* not successful; optimized branch; errno message may be incorrect */
	if (unlikely((long)ctx->ret < 0)) {
		LOG("Error reading from fd" + decstr(ctx->arg[SYSCALL_ARG0]) + ": " + strerror(errno) + "\n");
		return;
	}

	/* define constants for better readability of code */
	const size_t nr = ctx->ret;
	const int fd = ctx->arg[SYSCALL_ARG0];
	const LEVEL_BASE::ADDRINT buf = ctx->arg[SYSCALL_ARG1];
	// const size_t count = ctx->arg[SYSCALL_ARG2];

	if (fdset.find(fd) != fdset.end()) {
		/* set tags on read bytes */
		PROVLOG::ufd_t ufd = PROVLOG::ufdmap[fd];
		off_t read_offset_start = 0;
		size_t i = 0;

		if (IS_STDFD(fd)) { // counters for stdin/stdout/stderr are manually maintained
			read_offset_start = stdcount[fd];
			stdcount[fd] += nr;
		}
		else {
			read_offset_start = lseek(fd, 0, SEEK_CUR);
			if ( unlikely(read_offset_start < 0) ){
				LOG("Error on L" + decstr(__LINE__) + " lseek-ing on fd" + decstr(fd) + ": " + strerror(errno) + "\n");
				return;
			}
			read_offset_start -= nr;
		}

		// debug logging.
		LOG("----------------------------\n");
		LOG( "Read " + decstr(nr) +
				" bytes from fd" + decstr(fd) +
				":" + decstr((LEVEL_BASE::INT64)read_offset_start) +
				" to " + StringFromAddrint(buf) + ".\n"
		);
		LOG( "[" + StringFromAddrint(buf) + 
			" - " + StringFromAddrint(buf+32) +
			"] = " + std::string((char *)buf, MIN(nr, 32)) + "\n"
		);

		while(i<nr) {
			tag_t t = tagmap_getb(buf+i);
			t.set(ufd);
			tagmap_setb_with_tag(buf+i, t);
			
			LOG( "read:tags[" + StringFromAddrint(buf+i) + "] : " +
				tag_sprint(t) + "\n"
			);
			i++;
		}
	}
	else {
		/* clear tags for read bytes */
		size_t i = 0;
		while(i<nr) { tagmap_clrb(buf+i); i++; }			
	}
}

/*
 * readv(2) handler (taint-source)
 */
template<>
void post_readv_hook<libdft_tag_bitset>(syscall_ctx_t *ctx) {
	/* iterators */
	int i;
	struct iovec *iov;
	set<int>::iterator it;

	/* bytes copied in a iovec structure */
	size_t iov_tot;

	/* total bytes copied */
	size_t tot = (size_t)ctx->ret;

	LOG("readv called. ABORT.");
	/* readv() was not successful; optimized branch */
	if (unlikely((long)ctx->ret <= 0))
		return;
	
	/* get the descriptor */
	it = fdset.find((int)ctx->arg[SYSCALL_ARG0]);

	/* iterate the iovec structures */
	for (i = 0; i < (int)ctx->arg[SYSCALL_ARG2] && tot > 0; i++) {
		/* get an iovec  */
		iov = ((struct iovec *)ctx->arg[SYSCALL_ARG1]) + i;
		
		/* get the length of the iovec */
		iov_tot = (tot >= (size_t)iov->iov_len) ?
			(size_t)iov->iov_len : tot;
	
		/* taint interesting data and zero everything else */	
		if (it != fdset.end())
			/* set the tag markings */
			tagmap_setn((size_t)iov->iov_base, iov_tot);
		else
			/* clear the tag markings */
			tagmap_clrn((size_t)iov->iov_base, iov_tot);

			/* housekeeping */
			tot -= iov_tot;
		}
}

/* vim: set noet ts=4 sts=4 sw=4 ai : */
