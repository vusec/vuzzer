#
# NSL DFT library (libdft)
#
# Columbia University, Department of Computer Science
# Network Security Lab
#
# Vasileios P. Kemerlis (vpk@cs.columbia.edu)
#

# variable definitions
CXXFLAGS	+= -Wall -Wno-unknown-pragmas -c		\
		   -fomit-frame-pointer -std=c++11 -O3		\
		   -fno-strict-aliasing -fno-stack-protector	\
		   -DBIGARRAY_MULTIPLIER=1 -DUSING_XED		\
		   -DTARGET_IA32 -DHOST_IA32 -DTARGET_LINUX	\
		   # -DHUGE_TLB -mtune=core2
ARFLAGS		= rcsv
H_INCLUDE	+= -I. -I$(PIN_INCLUDE)				\
		   -I$(PIN_INCLUDE)/gen				\
		   -I$(PIN_XED_INCLUDE)				\
		   -I$(PIN_ROOT)/extras/components/include
OBJS		= libdft_api.o libdft_core.o syscall_desc.o tagmap.o tag_traits.o
LIB		= libdft.a

# phony targets
.PHONY: all sanity clean

# get system information
OS=$(shell uname -o | grep Linux$$)			# OS
ARCH=$(shell uname -m | grep "x86_64\|86$$")		# arch
KVER=$(subst -, ,$(subst ., ,$(shell uname -r)))	# kernel version (temp)

# kernel version in compact format (e.g., 2.6.26-2-686-bigmem is 2626)
KERN_VER=$(join $(word 1,$(KVER)),$(join $(word 2,$(KVER)),$(word 3,$(KVER))))

# default target (build libdft only)
all: sanity $(LIB)

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
ifneq ($(realpath $(PIN_ROOT)/extras/xed-ia32/include),)
PIN_XED_INCLUDE=$(PIN_ROOT)/extras/xed-ia32/include
else
PIN_XED_INCLUDE=$(PIN_ROOT)/extras/xed2-ia32/include
endif
# check need for cross-compile.
ifeq ($(findstring "x86_64", $(ARCH)),)
CXXFLAGS += -m32 
endif

# libdft
$(LIB): $(OBJS) config.h
	$(AR) $(ARFLAGS) $(@) $(OBJS)
	
# libdft_api
libdft_api.o: libdft_api.c libdft_api.h branch_pred.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# libdft_core
libdft_core.o: libdft_core.c libdft_core.h branch_pred.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# syscall_desc
syscall_desc.o: syscall_desc.c syscall_desc.h branch_pred.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

# tagmap
tagmap.o: tagmap.c tagmap.h tagmap_custom.h branch_pred.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.c)

tag_traits.o: tag_traits.cpp tag_traits.h 
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(H_INCLUDE) -o $(@) $(@:.o=.cpp)
# clean (libdft)
clean:
	rm -rf $(OBJS) $(LIB)
