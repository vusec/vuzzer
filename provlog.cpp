#include "provlog.H"

/* Array that maps fds to ufds. Unlike fds which are recycled, ufds
 * increase monotonically. This makes them suitable for use as taint
 * marks.
 */
PROVLOG::UFDMap PROVLOG::ufdmap;

/* Set of watched fds - maybe change this to bitset? */
std::set<int> fdset;

/* Counters for stdin/stdout/stderr.
 * TODO: Maybe this should be generalized. I.e. maintain counters for
 * all fds where isatty(fd) returns true.
 */
off_t stdcount[STDFD_MAX];

/* Raw provenance output stream. */
std::ofstream PROVLOG::rawProvStream;

/* Current executable name and pid.
 * XXX: Check if this works correctly while following execv().
 */
std::string exename("N/A");
pid_t pid;

/* vim: set noet ts=4 sts=4 sw=4 ai : */
