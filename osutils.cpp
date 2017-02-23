#include "osutils.H"
#include <string>

#if defined(TARGET_LINUX)

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#define __PROC_SELF_FD "/proc/self/fd"


std::string filename;

std::string fdname(int fd) {
	char ppath[PATH_MAX];
	char fpath[PATH_MAX];
	int w;

	/* create string for fd link path in /proc */
	w = snprintf(ppath, PATH_MAX*sizeof(char), "%s/%d", __PROC_SELF_FD, fd);
	assert(w < (int)(PATH_MAX*sizeof(char)));

	/* read link and return results */
	w = readlink(ppath, fpath, PATH_MAX*sizeof(char));
	if (w < 0) {
		return std::string(strerror(errno));
	}
	else if (w >= PATH_MAX) {
		/* terminate string and return */
		fpath[PATH_MAX-1] = '\0';
		return std::string(fpath)+std::string("...");
	}
	else {
		/* terminate string */
		fpath[w] = '\0';
		return std::string(fpath);
	}

	/* return something to make compiler happy */
	return NULL;
}

#elif defined(TARGET_MAC) || defined(TARGET_WINDOWS)

std::string fdname(int fd) {
	// Not implemented yet.
	// See: http://stackoverflow.com/a/13544447/277172 (Mac)
	//		http://stackoverflow.com/a/1188803/277172 (Windows)
	assert(0);
	return std::string("N/A");
}

#endif

/* vim: set noet ts=4 sts=4 sw=4 ai : */
