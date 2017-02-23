CXXFLAGS	+= -Wall -fomit-frame-pointer -std=c++11 -O3	\
		  -fno-strict-aliasing -fno-stack-protector	\
		  -DBIGARRAY_MULTIPLIER=1 -DUSING_XED		\
		  -DTARGET_IA32 -DHOST_IA32 -DTARGET_LINUX
CXXFLAGS_SO	+= -Wl,--hash-style=sysv -Wl,-Bsymbolic -shared \
		   -Wl,--version-script=$(PIN_INCLUDE)/pintool.ver
ARFLAGS		= rcsv
LIBS		+= -ldft -ldft_test_api -lpin -lxed -ldwarf -lelf -ldl # -liberty
H_INCLUDE	+= -I. -I$(PIN_INCLUDE) -I$(PIN_INCLUDE)/gen	\
		   -I$(PIN_ROOT)/extras/xed2-ia32/include	\
		   -I$(PIN_ROOT)/extras/components/include \
		   -I../src
L_INCLUDE	+= -L. -L../src -L$(PIN_ROOT)/extras/xed2-ia32/lib	\
		-L$(PIN_ROOT)/ia32/lib -L$(PIN_ROOT)/ia32/lib-ext

API_SRC		= libdft_test_api.c
API_OBJS	= $(API_SRC:.c=.o) 
API_LIB		= libdft_test_api.a

TOOL_SRC	= libdft_test_tool.c
TOOL_OBJS	= $(TOOL_SRC:.c=.o) 
TOOL		= $(TOOL_OBJS:.o=.so)

TEST_SRC	= $(wildcard test_*.cpp)
TEST_OBJS	= $(TEST_SRC:.cpp=.o)
TESTS		= $(TEST_OBJS:.o=)

# phony targets
.PHONY: all sanity clean api tool tests 

# get system information
OS=$(shell uname -o | grep Linux$$)			# OS
ARCH=$(shell uname -m | grep "x86_64\|86$$")		# arch

# default target (build libdft only)
all: sanity api tests tool 

# sanity checks (i.e., PIN_ROOT, OS, architecture)
sanity:
# check if PIN_ROOT variable is defined
ifndef PIN_ROOT
	$(error "PIN_ROOT environment variable is not set")
endif
# check the OS (must be Linux)
ifeq ($(strip $(OS)),)
	$(error "This version of libdft is for Linux only")
endif
# check the architecture (must be x86, i386, i486, i686, ...)
ifeq ($(strip $(ARCH)),)
	$(error "This version of libdft is for x86 and x86_64 only")
endif

# set the location of include files
ifneq ($(realpath $(PIN_ROOT)/source/include/pin.H),)
PIN_INCLUDE=$(PIN_ROOT)/source/include
else
PIN_INCLUDE=$(PIN_ROOT)/source/include/pin
endif
# check need for cross-compile.
ifeq ($(findstring "x86_64", $(ARCH)),)
CXXFLAGS += -m32 
CXXFLAGS_SO += -m32
endif

api: $(API_LIB)

tool: $(TOOL)

tests: $(TESTS)

$(API_LIB): $(API_OBJS) 
	$(AR) $(ARFLAGS) $@ $?

$(API_OBJS): $(API_SRC)
	$(CXX) $(CXXFLAGS) -c $(H_INCLUDE) -o $(@) $(@:.o=.c)

$(TOOL): $(TOOL_OBJS) $(API_LIB) 
	$(CXX) $(CXXFLAGS_SO) $(L_INCLUDE) -o $@ $< $(LIBS)

$(TOOL_OBJS): $(TOOL_SRC) 
	$(CXX) $(CXXFLAGS) -c $(H_INCLUDE) -o $(@) $(@:.o=.c)

$(TESTS): $(API_OBJS) $(TEST_OBJS)
	$(CXX) $(CXXFLAGS) -o $(@) -L../src -L. $(addsuffix .o, $@) -ldft_test_api -ldft 
$(TEST_OBJS): $(TEST_SRC) 
	$(CXX) $(CXXFLAGS) -c $(H_INCLUDE) -o $(@) $(@:.o=.cpp) 

clean:
	$(RM) $(API_OBJS) $(API_LIB) $(TOOL_OBJS) $(TOOL) $(TEST_OBJS) $(TESTS) *.log
