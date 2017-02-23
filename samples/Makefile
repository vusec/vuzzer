CC=gcc
CFLAGS=-O0 -DTARGET_IA32 -DHOST_IA32 -DTARGET_LINUX -m32 -Wall

ALL_TESTS=#test_aggr test_atoi test_printf
ALL_TARGETS=$(ALL_TESTS) ccombine sgrep upcase tricky #cplow cprefix pickshort charn tricky sum xor
DEBUG_OUT=*.id* *.nam

.PHONY: all
all: $(ALL_TARGETS)

test_atoi: test_atoi.c
	$(CC) $(CFLAGS) -DBSD_ATOI $^ -o $@

clean:
	rm -f $(ALL_TARGETS) $(DEBUG_OUT)
