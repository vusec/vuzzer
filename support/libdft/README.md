# libdft: Practical Dynamic Data Flow Tracking

## Introduction
   Dynamic data flow tracking (DFT) deals with the tagging and tracking of
"interesting" data as they propagate during program execution. DFT has been
repeatedly implemented by a variety of tools for numerous purposes, including
protection from buffer overflow and cross-site scripting attacks, analysis of
legitimate and malicious software, detection and prevention of information
leaks, etc. libdft is a dynamic DFT framework that is at once fast, reusable,
and works with commodity software and hardware. It provides an API, which can
be used to deliver DFT-enabled tools that can be applied on unmodified binaries
running on common operating systems and hardware, thus facilitating research
and rapid prototyping.

---------------------------------------------------------------------

## Installation & Usage
   libdft relies on [Intel Pin](http://www.pintool.org), which is a dynamic binary
instrumentation (DBI) framework from Intel. In order to install libdft you first
need a working copy on the latest Pin build, as well as the essential build
tools for GNU/Linux (i.e., GCC, GNU Make, etc). After downloading and installing
Intel Pin please follow the [libdft installation instructions](INSTALL.md).

### Tools
   libdft is designed to facilitate the creation of "Pin tools" that employ
dynamic DFT. As the name implies, libdft is also a shared library, which can be 
used to transparently perform DFT on binaries. Additionally, it provides an API 
that enables tool authors to adjust the applied DFT by specifying data sources
and sinks, and customize the tag propagation policy. We have included three
simple Pin tools inside the [`tools`](tools) subdirectory to aid the development of
DFT-powered Pintools:

  * [`nullpin`](tools/nullpin.c) is essentially a null tool
    that runs a process using Pin without any form of instrumentation or analysis.
    This tool can be used to measure the overhead imposed by Pin's runtime
    environment.
  * [`libdft`](tools/libdft.c) uses libdft to apply DFT on the application being
    executed, but does not use any of the API functions to define data sources and
    sinks (i.e., it does not customize the applied DFT).
    This tool can be used to evaluate the overhead imposed by libdft.
  * [`libdft-dta`](tools/libdft-dta.c) is an example tool that uses the API
    of libdft, and serves as template for future meta-tools.
    In particular, it implements a dynamic taint analysis (DTA)
    platform by transparently utilizing DFT in unmodified x86 Linux binaries.

   DTA operates by tagging all data coming from the network as "tainted",
tracking their propagation, and alerting the user when they are used in a way
that could compromise his system. In this case, the network is the source of
"interesting" data, while instructions that are used to control a program's flow
are the sinks. For the x86 architecture, these are jumps and function calls with
non-immediate operands, as well as function returns. Oftentimes, attackers are
able to manipulate the operands of such instructions by abusing various types of
software memory errors such as buffer overflows, format string vulnerabilities, 
dangling pointers, etc. They can then seize control of a program by redirecting 
execution to existing code (e.g., return-to-libc, ROP), or their own injected
instructions. libdft-dta checks if tainted data are used in indirect control
transfers, and if so, it halts execution with an informative message containing 
the offending instruction and the contents of the instruction pointer EIP.

### Usage
   After building both libdft and the accompanying tools (i.e., `nullpin`,
`libdft`, and `libdft-dta`), you can apply them directly in unmodified x86
Linux binaries as follows (assuming that you have added Pin's location to
your `PATH`, and installed libdft in your home directory):

```shell
pin -follow_execv -t ~/libdft/tools/nullpin.so -- <executable>
```

#### Arguments processed by Pin
  * `-follow_execv`: Instructs Pin to also instrument all processes spawned
     using the `exec(3)` class system calls by the program.
  * `-t`: Specifies the Pin tool to be used.

#### Tool-specific arguments
  Arguments which are specific to the used Pin tool must be placed after the tool
name and before `--` in the command line. The supplied `nullpin` and `libdft` tools
"dummies" and hence take no arguments. For `libdft-dta`, the following arguments can
be specified:

  * `-l <filename>`: specify a file where alerts and policy violations will be
    logged.
  * `-s [0|1]`: Turn on/off tainting for data originating from `stdin`.
  * `-f [0|1]`: Turn on/off tainting for data originating from files.
  * `-n [0|1]`: Turn on/off tainting for data originating from the network.

---------------------------------------------------------------------

## Research
   Following are some publications that rely on libdft:

  * **[libdft: Practical Dynamic Data Flow Tracking for Commodity Systems][1].**
    *Vasileios P. Kemerlis, Georgios Portokalidis, Kangkook Jee, and Angelos D. Keromytis.*
    In Proceedings of the *8th ACM SIGPLAN/SIGOPS International Conference on Virtual Execution Environments (VEE)*. March 2012, London, UK.
  * **[A General Approach for Efficiently Accelerating Software-based Dynamic Data Flow Tracking on Commodity Hardware][2].**
    *Kangkook Jee, Georgios Portokalidis, Vasileios P. Kemerlis, Soumyadeep Ghosh, David I. August, and Angelos D. Keromytis.*
    In Proceedings of the *19th Internet Society (ISOC) Symposium on Network and Distributed System Security (NDSS)*. February 2012, San Diego, CA.

[1]: http://nsl.cs.columbia.edu/papers/2012/libdft.vee12.pdf
[2]: http://nsl.cs.columbia.edu/papers/2012/tfa.ndss12.pdf
