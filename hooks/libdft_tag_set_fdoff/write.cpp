#include "hooks/hooks.H"

#include <map>
#include <set>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "libdft_api.h"
#include "tagmap.h"
#include "pin.H"

#include "dtracker.H"
#include "osutils.H"


#include "pin.H"


/* 
	Output aggregation information
	-------------------------------

	DTracker does two types of aggregation:
		a. Range mapping. 
			I.e. for 0<=i<len, byte b[off_write+i] is tainted with ufdX:(off_tag+i). 
		b. Repetetion mapping.
			I.e. for 0<=i<len, byte b[off_write+i] is tainted with ufdX:off_tag.

	To calculate the mappings, we update two maps for each byte written:
		a. ranges_prev map contains the ranges that were "running" after
		   processing the previous written byte.
		b. ranges map starts empty and is updated to contain the ranges that
		   are "running" after processing the taint marks of the current byte.

	Essentially, the algorith goes like this:

	for m in wbuf:
		for ufdX:Y in m.tag:
			if ufdX:Y in ranges_prev:
				# update REP range
				ranges[ufdX:Y] = {REP, ranges_prev[ufdX:Y].length+1}
				del ranges_prev[ufdX:Y]
			elif ufdX:(Y-1) in ranges_prev:
				# update SEQ range
				ranges[ufdX:Y] = {SEQ, ranges_prev[ufdX:Y-1].length+1}
				del ranges_prev[ufdX:Y-1]
			else:
				# create new range
				ranges[ufdX:Y] = {NONE, 1}

		# ranges_prev now contains ranges that are no longer running
		dump(ranges_prev)
		ranges_prev = ranges
		ranges = {}
	dump(ranges_prev)

	The above is slightly simplified. In practice, when a taint mark may 
	belong to either a REP range or a SEQ range, we make sure it goes to the
	REP range.
*/

// #define __DEBUG_SYSCALL_WRITE
#ifdef __DEBUG_SYSCALL_WRITE
static inline std::string __RANGE2STR(const range_map_t & rmap) {
	std::string s;
	for (auto &r : rmap) {
		s += decstr(r.first.first) + ":" + decstr(r.first.second) + 
			"(" + decstr((int)r.second.type) + "," + decstr(r.second.start) +
			"," + decstr(r.second.length) + ") ";
	}
	return s;
}
#endif

/*
 * write(2) handler (taint-sink)
 * 
 * Signature: ssize_t write(int fd, const void *buf, size_t count);
 */
#define DEF_SYSCALL_WRITE
#include "hooks/syscall_args.h"
template<>
void post_write_hook<libdft_tag_set_fdoff>(syscall_ctx_t *ctx) {
	/* ignore write() on not watched fd */
	if (unlikely(fdset.find(_FD) == fdset.end()))
		return;

	/* write() was not successful; optimized branch; errno message may be incorrect */
	if (unlikely(_N_WRITTEN < 0)) {
		LOG("ERROR " _CALL_LOG_STR + " (" + strerror(errno) + ")\n");
		return;
	}

	LOG("OK    " _CALL_LOG_STR + "\n");

	const ufd_t ufd = ufdmap.get(_FD);
	off_t write_begin;
	range_map_t ranges;
	range_map_t ranges_prev;

	/* calculate begining of write */
	if (IS_STDFD(_FD)) {
		write_begin = stdcount[_FD];
		stdcount[_FD] += _N_WRITTEN;
	}
	else {
		write_begin = lseek(_FD, 0, SEEK_CUR) - _N_WRITTEN;
		if ( unlikely(write_begin < 0) ){
			LOG("Error on L" + decstr(__LINE__) + " lseek-ing on fd" + decstr(_FD) + ": " + strerror(errno) + "\n");
			return;
		}
	}

	for(ssize_t i=0; i<_N_WRITTEN; i++) { //loop through memory locations
		tag_t tag = tagmap_getb(_BUF+i);

#ifdef __DEBUG_SYSCALL_WRITE
		LOG("---------------------- " + std::string((char *)(_BUF+i), 1) + "\n");
		LOG("RANGES " + __RANGE2STR(ranges) + "\n");
		LOG("RANGES_PREV " + __RANGE2STR(ranges_prev) + "\n");
#endif

		for (auto & tm : tag) { //loop taint marks for specific location

			// check if a single taint mark from the input is repeated in the output
			auto rlookup = tm;
			auto range_it = ranges_prev.find(rlookup);
			if (range_it != ranges_prev.end()) {
				// LOG("C1\n");
				auto range_last = (*range_it).first;
				auto range_info = (*range_it).second;

				switch(range_info.type) {
					case range_info_t::SEQ:
						// adjust SEQ range
						range_last.second--;
						range_info.length--;
						ranges_prev.insert(range_it, std::make_pair(range_last, range_info));
						ranges_prev.erase(range_it);

						// add a new REP range to next range set
						ranges.insert(std::make_pair(tm, (range_info_t){range_info_t::REP, i-1, 2}));
						continue;

					case range_info_t::NONE:
						// set range type to REP
						range_info.type = range_info_t::REP;

					case range_info_t::REP:
						// add info to next range set
						range_info.length++;
						ranges.insert(std::make_pair(tm, range_info));

						// remove info from previous range set
						ranges_prev.erase(range_it);
						continue;
				}
			}

			// check if a sequence of taint marks from the input also appears in the output
			rlookup = tm;
			rlookup.second -= 1;
			range_it = ranges_prev.find(rlookup);
			if (range_it != ranges_prev.end()) {
				// LOG("C2\n");
				auto range_info = (*range_it).second;

				switch(range_info.type) {
					case range_info_t::REP:
						// start a new range - we won't touch the old one
						ranges.insert(std::make_pair(tm, (range_info_t){range_info_t::NONE, i, 1}));
						continue;

					case range_info_t::NONE:
						// set range type to SEQ
						range_info.type = range_info_t::SEQ;
				
					case range_info_t::SEQ:
						// add info to next range set
						range_info.length++;
						ranges.insert(std::make_pair(tm, range_info));

						// remove info from previous range set
						ranges_prev.erase(range_it);
						continue;		
				}
			}

			// add taint mark as a new range
			// LOG("C3\n");
			rlookup = tm;
			ranges.insert(std::make_pair(rlookup, (range_info_t){range_info_t::NONE, i, 1}));

		} //loop taint marks

#ifdef __DEBUG_SYSCALL_WRITE
		LOG("~~~~~~~~~~~~~~\n");
		LOG("RANGES " + __RANGE2STR(ranges) + "\n");
		LOG("RANGES_PREV " + __RANGE2STR(ranges_prev) + "\n");
#endif

		//dump output for pattern sequences that were broken
		for (auto &tm : ranges_prev)
			PROVLOG_WRITE_RANGE(ufd, write_begin, tm.first, tm.second);

		// swap the two range sets and clear the ranges for next iteration
		ranges.swap(ranges_prev);
		ranges.clear();

	} //loop memory locations

	//dump the remaining pattern sequences
	for (auto &tm : ranges_prev)
		PROVLOG_WRITE_RANGE(ufd, write_begin, tm.first, tm.second);
}
#define UNDEF_SYSCALL_WRITE
#include "hooks/syscall_args.h"

template<>
void post_writev_hook<libdft_tag_set_fdoff>(syscall_ctx_t *ctx) {
	LOG("Writev. Not supported yet.\n");
}

/* vim: set noet ts=4 sts=4 sw=4 ai : */
