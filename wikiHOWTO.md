# VUzzer:

Version: 0.0.
This is an early (and uncleaned!) release of the tool. Please excuse us. The next (future) release is aimed as providing the following:
- 64-bit support
- For static analysis component, perform the analysis using some open-source tool, like angr or miasm. Currently, it is done using IDA.
- A cleaner code!


ADDED: An improved algorithm for calculating BB weights is implemented in the file "bb-weight-new.py". Please use that to get more precise information. However, it takes longer to compute the weights (specially for larger/complex code). 


## A step-by-step guide to run VUzzer: 
Some acronyms:
- BB: basib-block
- SUT: software undet test (application that you want to fuzz)
- DTA: dynamic taintflow analysis

Make sure that you have installed all the components as described in README.md.
1. Let us first set some environment variables. Run the following commands:
```sh
$ cd vuzzer-code
$ export PIN_ROOT=$(pwd)/pin #assuming you are using pintool forder as comes with the repo.
$ echo 0 |sudo tee /proc/sys/kernel/randomize_va_space
$ echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```
2. There are two files that are important to run VUzzer- runfuzzer.py and config.py. runfuzzer.py is the main execution script. One the cmd, type the following:
```sh
$ python runfuzzer.py -h
usage: runfuzzer.py [-h] -s SUT -i INPUTD -w WEIGHT -n NAME [-l LIBNUM] -o
                    OFFSETS [-b LIBNAME]

VUzzer options parser
```
It is important to understand these options. We'll discuss more advanced options later. In order to explain with an example, we'll use one of LAVA binaries- `who`. We have provided precompiled LAVA binaries in `bin` forlder of parent directory. We compiled the LAVA binaries with default options. Following will help to check if you can also use those binaries (directly).
```sh
$ ldd bin/who
    linux-gate.so.1 =>  (0xb7fff000)
    libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0xb7e39000)
    /lib/ld-linux.so.2 (0x80000000)
$  gcc --version
gcc (Ubuntu 4.8.4-2ubuntu1~14.04.3) 4.8.4
Copyright (C) 2013 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
$ uname -a
Linux ubuntu 3.13.0-91-generic #138-Ubuntu SMP Fri Jun 24 15:58:13 UTC 2016 i686 i686 i686 GNU/Linux
```
 `-s` (SUT commandline): `"bin/who %s"`. For VUzzer to understand the place for the input file for a given SUT, we put a placeholder in the form of %s. All other arguments occupy their place as usual.
 
 `-i` (seed input directory (relative path)): `"datatemp/utmp/"`. this directory contains seed inputs that are used to start fuzzing. For each SUT, we should create a folder in datatemp directory and copy 4 (min) seed files. The size of the file matters a lot, so try using files of size less than 20 kb (upper limit is for cases like media files). 
 
 `-w` (path of the pickle file(s) for BB wieghts (separated by comma in case there are two): `"idafiles/who.pkl"`. This is the step that depends on IDA. The binary that we want to fuzz (who, in this case) is opened in IDA and we run the idapython based script *BB-weightv4.py* within IDA. This step creates two separate pickle files: who.pkl and who.names. Copy these files to some location. Defaulat location is idafiles/ folder. If we also want to monitor a dynamic library used by SUT, we also repeat the above process for the library. And in this case, we need to supply two files for this option, i.e. `-w "idafiles/who.pkl,idafiles/lib.pkl"`, assuming name of the dynamic library is `lib.so`. An improved algorithm for calculating BB weights is implemented in the file "bb-weight-new.py". Please use that to get more precise information. However, it takes longer to compute the weights (specially for larger/complex code). 
 
 `-n` (Path of the pickle file(s) containing strings from `CMP` inst (separated by comma if there are two)): `-n "idafiles/who.names"`. As we mentioned above, *BB-weightv4.py* creates two files and in this option, we supply the second file with `.names` extn. If there is a library to monitor, we supply its .name file also as `-n "idafiles/who.names,idafiles/lib.names"`.
 
 `-l` (Nunber of binaries to monitor (only application or used libraries): Its default value is 1, which is the case when we want to fuzz only the SUT. If we want to fuzz a dnamic lib also, we set `-l 2`.
 
 `-o` (base-address of application and library (if used), separated by comma): `-o "0x00000000"`. This is the default value also. If we are monitoring a lib, we provide its load-address also as `-o "0x00000000, 0x00000000"`. Here is a step that we need to do manually to know the load-address of SUT and dynamic library. When we run our fuzzer with the default options, it will stop with an error message that load-addres changed. At this time, we need to open *imageOffset.txt* file to see the load-addess of SUT and the dynamic library. As we disable ASLR, we can use these addresses with -o option to run VUzzer again and it will run happily (Yes, this will be automated in the next release!!).
 
 `-b` (library name to monitor): `-b ''`. Its default value is empty string. However, when we want to monitor a lib, we need to set this option as `-b "lib_name"`. Normally we skip any extn.
 
 These are the main options that are needed to set VUzzer. There are few more advance options that can be set in config.py file. we'll see some of them later.
 
 3. Having understood the main option, we can launch VUzzer as follows:
```sh
 python runfuzzer.py -s '/PATH_TO_vuzzer-code/bin/who %s' -i 'datatemp/utmp/' -w 'idafiles/who.pkl' -n idafiles/who.names -o '0x00000000'
 ```
 4. Per genration, some stats are printed in stats.log file. 
 5. If VUzzer finds a crash, it copies the crash triggering input in outd/crashInputs folder. The input file name is indicatr of time and type of the crash. 

## Advance Configuration Options
VUzzer is highly configurable fuzzer. All such configurable options are defined in config.py file. Each defined option has some explanation about itself. Following are few important options that one can set for a specific scenario.
- POPSIZE: how many input per generation should be generated.
- BESTP: how many input will be considered to be part of next generation.
- GENNUM: how many generations VUzzer should run for.
- MOSTCOMNLAST: default value should be 8. A lower value aggressively tries to explore new paths, which means more bad inputs! 
-STOPONCRASH: if you want VUzzer to stop on 1st crash, set this to True.

In the near future, we'll explain more of these features by presenting relevant examples. Meanwhile, feel free to ask me about via mail (sanjayr@ymail.com).
## If there are issues (other than the bad documentation ;) ), please let me know.

