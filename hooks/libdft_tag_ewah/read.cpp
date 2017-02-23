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
#define DEF_SYSCALL_READ
#include "hooks/syscall_args.h"

template<>
void post_read_hook<libdft_tag_ewah>(syscall_ctx_t *ctx) {
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

        LOG("OK    " _CALL_LOG_STR + "\n");
	if (fdset.find(fd) != fdset.end()) {
		/* set tags on read bytes */
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
			tag_t ts_prev = tagmap_getb(buf+i);
			tag_t ts;
			ts.set(read_offset_start + i);
			tagmap_setb_with_tag(buf+i, ts);

			// TODO : Add if condition of Knob i.e. only store when ReadKnob is true
//		        read_offset << tag_sprint(tagmap_getb(buf+i)) << endl;


			LOG( "read:tags[" + StringFromAddrint(buf+i) + "] : " +
				tag_sprint(ts_prev) + " -> " +
				tag_sprint(tagmap_getb(buf+i)) + "\n"
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

#define UNDEF_SYSCALL_READ
#include "hooks/syscall_args.h"
/*
 * readv(2) handler (taint-source)
 */
template<>
void post_readv_hook<libdft_tag_ewah>(syscall_ctx_t *ctx) {
	/* iterators */
	LOG("readv(2) not supported");
}

#define DEF_SYSCALL_PREAD
#include "hooks/syscall_args.h"

template<>
void post_pread_hook<libdft_tag_ewah>(syscall_ctx_t *ctx) {
	LOG("pread(2) not supported");
	const size_t nr = ctx->ret;
	const int fd = ctx->arg[SYSCALL_ARG0];
	const LEVEL_BASE::ADDRINT buf = ctx->arg[SYSCALL_ARG1];
	//const size_t count = ctx->arg[SYSCALL_ARG2];
	const off_t read_offset_start = ctx->arg[SYSCALL_ARG3];

                LOG("OK    " _CALL_LOG_STR + "\n");

	if (fdset.find(fd) != fdset.end()) {
		/* set tags on read bytes */
	//	off_t read_offset_start = (off_t) ;
		size_t i = 0;

		if (IS_STDFD(fd)) { // counters for stdin/stdout/stderr are manually maintained
			//read_offset_start = stdcount[fd];
			stdcount[fd] += nr;
		}
                else {
                        //read_offset_start = lseek(fd, 0, SEEK_CUR);
                        if ( unlikely(read_offset_start < 0) ){
                                LOG("Error on L" + decstr(__LINE__) + " pread " + decstr(fd) + ": " + strerror(errno) + "\n");
                                return;
                        }
                        //read_offset_start -= nr;
                }

                // debug logging.
                LOG("----------------------------\n");
                LOG( "Pread " + decstr(nr) +
                                " bytes from fd" + decstr(fd) +
                                ":" + decstr((LEVEL_BASE::INT64)read_offset_start) +
                                " to " + StringFromAddrint(buf) + ".\n"
                );
                LOG( "[" + StringFromAddrint(buf) +
                        " - " + StringFromAddrint(buf+32) +
                        "] = " + std::string((char *)buf, MIN(nr, 32)) + "\n"
                );

                while(i<nr) {
                        tag_t ts_prev = tagmap_getb(buf+i);
                        tag_t ts;
                        ts.set(read_offset_start + i);
                        tagmap_setb_with_tag(buf+i, ts);

                        // TODO : Add if condition of Knob i.e. only store when ReadKnob is true
//                      read_offset << tag_sprint(tagmap_getb(buf+i)) << endl;


                        LOG( "read:tags[" + StringFromAddrint(buf+i) + "] : " +
                                tag_sprint(ts_prev) + " -> " +
                                tag_sprint(tagmap_getb(buf+i)) + "\n"
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
#define UNDEF_SYSCALL_PREAD
#include "hooks/syscall_args.h"

/* vim: set noet ts=4 sts=4 sw=4 ai : */
