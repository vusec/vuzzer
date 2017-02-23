#ifndef __PROVLOG_H__
#define __PROVLOG_H__

#include <iostream>
#include <fstream>
#include <string>
#include <array>
#include <set>
#include <map> // ?

#include <pin.H>
#include <unistd.h>
#include <fcntl.h>
#include "dtracker.H"

/* Maximum open files per process. */
#define MAX_OPEN_FILES 1024

/* macros related to stdin/stdout/stderr */
#define STDFD_MAX ( MAX( MAX(STDIN_FILENO, STDOUT_FILENO), STDERR_FILENO ) + 1 )
#define IS_STDFD(fd) ( (fd == STDOUT_FILENO) || (fd == STDIN_FILENO) || (fd == STDERR_FILENO) )


/**** data types and externals ************************************/
namespace PROVLOG {

typedef UINT32 ufd_t;

/*
 * UFDMap maps program fds (as used by the program) to ufds.
 * Normal fds are not suitable for use as taint marks in taint flow
 * analysis becaƒuse are "recycled" by the os. This will eventually
 * lead to misattribution of some data.
 *
 * Unlike fds which are recycled by the OS, ufds increase monotonically.
 * This makes ufds suitable for use in taint flow analysis.
 */
class UFDMap {
	public:
		ufd_t operator[](int fd) {
			if (this->map[fd] == 0)
				this->map[fd] = this->next++;
			return this->map[fd];
		}
		ufd_t del(int fd) {
			ufd_t ufd = map[fd];
			map[fd] = 0;
			return ufd;
		}
	private:
		ufd_t next = 1;
		std::array<ufd_t, MAX_OPEN_FILES> map;
};

extern UFDMap ufdmap;
} // namespace PROVLOG

/* Set of watched fds. */
extern std::set<int> fdset;

/* Counters for stdin/stdout/stderr. */
extern off_t stdcount[STDFD_MAX];

/* Current executable name and pid. */
extern std::string exename;
extern pid_t pid;

/**** output macros and inlines ***********************************/
typedef struct {
	enum {NONE, SEQ, REP} type;
	ssize_t start;
	ssize_t length;
} range_info_t;
static const char * range_type_strings[] = { "NONE", "SEQ", "REP" };
// typedef std::map<tag_traits<tag_t>::inner_type, range_info_t> range_map_t;

namespace PROVLOG {

/* Raw provenance output stream. */
extern std::ofstream rawProvStream;

/* inline functions for raw provenance logging */
static inline void open(const ufd_t ufd, const std::string & fdname, const int flags, const int created) {
	rawProvStream << "o:ufd" << ufd << ":" << fdname << std::endl;

	// Unless the the O_WRONLY flag is on, the file descriptor can be read.
	if (! (flags&O_WRONLY) )
		rawProvStream << "u:" << exename  << ":" << fdname << std::endl;
	
	// Emit a generated line if needed.
	if (flags & (O_WRONLY|O_RDWR)) {
		if (created) {
			rawProvStream << "#g:created" << std::endl;
			rawProvStream << "g:c:" << exename  << ":" << fdname << std::endl;
		}
		else if (flags & O_TRUNC) {
			rawProvStream << "#g:truncated" << std::endl;
			rawProvStream << "g:t:" << exename  << ":" << fdname << std::endl;
		}
		else {
			// Updated means that it is opened for writing.
			// TODO: Currently this is translated to a wasGeneratedBy edge only
			//       if some tainted bytes are written.
			rawProvStream << "#g:updated" << std::endl;
			rawProvStream << "g:u:" << exename  << ":" << fdname << std::endl;
		}
	}
	
	// TODO: (low urgency) emit a truncation line if O_TRUNC is included in the flags
}
static inline void close(const ufd_t ufd) {
	rawProvStream << "c:ufd" << ufd << std::endl;
}
static inline void exec(const std::string & exename, pid_t pid) {
	rawProvStream << "x:" << pid << ":" << exename << std::endl;
}

// used for DLIBDFT_TAG_TYPE=libdft_tag_bitset
static inline void write(const ufd_t ufd_origin, const ufd_t ufd_dest, const off_t write_begin, const off_t length) {
	const char *range_type = length > 1 ? range_type_strings[range_info_t::REP] : range_type_strings[range_info_t::NONE];
	rawProvStream << "w:" << range_type <<
		":ufd" << ufd_dest << ":" << write_begin <<
		":ufd" << ufd_origin << ":" << 0 <<
		":" << length << std::endl;
}

// used for DLIBDFT_TAG_TYPE=libdft_tag_set_fdoff
// static inline void PROVLOG_WRITE_RANGE(const ufd_t ofd, const off_t write_begin, const range_map_t::key_type last, const range_map_t::mapped_type & info) {
	// switch(info.type) {
	// 	case range_info_t::SEQ:
	// 		rawProvStream << "w:" << range_type_strings[info.type] <<
	// 			":ufd" << ofd << ":" << (write_begin+info.start) <<
	// 			":ufd" << last.first << ":" << (last.second-(info.length-1)) << 
	// 			":" << info.length << std::endl;
	// 		break;
	// 	case range_info_t::NONE:
	// 	case range_info_t::REP:
	// 		rawProvStream << "w:" << range_type_strings[info.type] <<
	// 			":ufd" << ofd << ":" << (write_begin+info.start) <<
	// 			":ufd" << last.first << ":" << last.second << 
	// 			":" << info.length << std::endl;
	// 		break;
	// }
// }

} // namespace PROVLOG

#endif

/* vim: set noet ts=4 sts=4 sw=4 ai : */
