#include "hooks/hooks.H"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "libdft_api.h"
#include "tagmap.h"
#include "pin.H"

#include "provlog.H"
#include "dtracker.H"
#include "osutils.H"


// TODO: Consider hooking mprotect(2).

char buf2[4];
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
void post_mmap2_hook<libdft_tag_ewah>(syscall_ctx_t *ctx) {
        if (unlikely(_ADDR == (ADDRINT)-1)) {
                LOG("ERROR " _CALL_LOG_STR + " (" + strerror(errno) + ")\n");
                return;
        }

        if (_FD >= 0 && fdset.find(_FD) != fdset.end()) {
                LOG("OK    " _CALL_LOG_STR + "\n");
		off_t offset_start;

		if(mmap_type == 0){
			LOG("Lseek \n");
			offset_start = lseek(_FD, 0, SEEK_CUR);
		}else if(mmap_type == 1){
			off_t fsize = lseek(_FD, 0, SEEK_END);
			UINT32 i = 0;
			offset_start = i +_FD_OFFSET;
			LOG("fd offset " + decstr((LEVEL_BASE::UINT32)fsize) +" "+ decstr((LEVEL_BASE::UINT32)offset_start) +decstr((unsigned long long)_FD_OFFSET) + "\n");
			if((UINT32)offset_start > (UINT32)fsize){
				//offset_start = 0;
				//LOG("libdft_dir\n");
				//libdft_die();
				//if(offset_start < 0){
				//	offset_start = 0;
				//}
				//ADDRINT * buf3 = (ADDRINT *)_ADDR;
				int nread = pread64(_FD, buf2, (ssize_t) 4, 0);
				LOG(decstr(_FD) + " " +  decstr(nread) + "\n");
				char *a = (char *)_ADDR;
				if(nread == 4){		
					//char *buf3 = StringFromAddrint(_ADDR).c_str();
				//	string s(buf2);
				//	string s1(a);
					//s1.push_back(b);
//					string s1(*(buf3));
					//LOG("%s\n",buf2);
				//	LOG(s + " " + s1);
				//	LOG("\n");
					if(strcmp(buf2, a) == 0){
						offset_start = 0;
					}else{
						LOG("libdft_die\n");
					//	free(buf2);
						libdft_die();
					}
				}else{
						LOG("libdft_die\n");
					//	free(buf2);
						libdft_die();
				}

				//free(buf2);
			}
		}
		//ADDRINT * mmapArgs = reinterpret_cast<ADDRINT *>(_ADDR_HINT);
		//LOG(StringFromAddrint(mmapArgs[0]) + " " + "\n");
                /* set tags on mapped area */
               // const PROVLOG::ufd_t ufd = PROVLOG::ufdmap[_FD];
                size_t i = 0;
                while(i<_LENGTH) {
                        tag_t t = tagmap_getb(_ADDR+i);
			tag_t ts;
                        ts.set(offset_start+i);
                        tagmap_setb_with_tag(_ADDR+i, ts);

                        LOG( "mmap:tags[" + StringFromAddrint(_ADDR+i) + "] : " +
                               tag_sprint(t) + " -> " + tag_sprint(tagmap_getb(_ADDR+i)) + "\n"
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
void post_munmap_hook<libdft_tag_ewah>(syscall_ctx_t *ctx) {
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
