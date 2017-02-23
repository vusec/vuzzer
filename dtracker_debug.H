#ifndef __DTRACKER_DEBUG_H__
#define __DTRACKER_DEBUG_H__

#include <string>
#include <sstream>
#include "tagmap.h"
#include "pin.H"

#define DT_DBG_MAGIC "Tsakas"
#define DT_DBG_MAGICLEN 6

inline std::string tag_memrange_sprint(ADDRINT addr, size_t n) {
	size_t i;
	std::stringstream ss;

	ss << "tags[" << StringFromAddrint(addr) << "][0:" << n-1 << "] = [";
	for (i=0; i<n-1; i++) {
		ss << i << ":" << tag_sprint(tagmap_getb(addr+i)) << ", ";
	}
	ss << i << ":" << tag_sprint(tagmap_getb(addr+i)) << "]";

	return ss.str();
}

inline int debug_gotmagic_backward(const void * const pt) {
	for (int i=0; i<DT_DBG_MAGICLEN; i++) {
		if (((char *)pt)[-i] != DT_DBG_MAGIC[DT_DBG_MAGICLEN-1-i])
			return 0;
	}
	return 1;
}

inline int debug_gotmagic_forward(const void * const pt) {
	for (int i=0; i<DT_DBG_MAGICLEN; i++) {
		if (((char *)pt)[i] != DT_DBG_MAGIC[i])
			return 0;
	}
	return 1;
}

void CheckMagicValue(INS ins, void *v);
#endif

/* vim: set noet ts=4 sts=4 sw=4 ai : */
