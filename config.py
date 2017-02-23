"""
This file contains configuration parameters of VUFuzzer

"""
import inspect
import os
#import run-conf

mydir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))

######################
#for PIN trace to work, run the following from the shell you will run your fuzzer:
# echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
# Also disable ASLR:
# echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
##################

# set path to Pin home where pin is found 
PINHOME=os.getenv('PIN_ROOT', "/home/sanjay/tools/pin-2.14")  + "/pin"
# for address reading, tell the size i.e. 32/64bit
BIT64=False

# set path to your pintool bbcounts.so
PINTOOL=mydir + "/obj-ia32/bbcounts2.so"
# and for taintflow pintoo
PINTNT=mydir+"/obj-ia32/dtracker.so"

# set file path to read executed BBs and their respective frequencies
BBOUT=mydir + "/outd/bbc.out"

# Set file path for crash hash info (this cannot be changed as pintool writes to this file)
CRASHFILE='crash.bin'

############################## argument setting  #######################
#set path of software under test (SUT)
SUT=''
# directory containing seed inputs
INITIALD=mydir

# set string that contains names of libraries (without any suffix after a DOT) to be monitored, searated by commas. This is used while launching pintool to monitor application being fuzzed.
LIBTOMONITOR= ''


# set number of libraries that were statically analyzed for BB weights. This is related to LIBTOMONITOR. There is one default entry for the main executable. NOTE: in the current implementation, we assume to have only ONE library to be used, i.e. max value for this is 2.
LIBNUM=1

# set path of each library's saved pickle files (two files for each lib) that will be read by the fuzzer. This is set in a list, whose length should be equal to LIBNUM. We have created two separate variables to mention these files. 1st one if for BB weights and 2nd one is for strings found in binaries.
LIBPICKLE=[]


NAMESPICKLE=[]


#set load offsets of the libraries of interest by observing pintool output for image load. You get this value by fisrt launching the application as trial and then reading the file imageOffset.txt.  
LIBOFFSETS=[]
##################################################

#INITIALD=mydir + "/datatemp/avi/"

# "##" is the place holder for input file that is changed on each iteration. while running, we need to replace '##' by that input
#SUTARG=["-fast","##"]

#this flag is set if we want to delete output files created by the SUT on executing each input.
CLEANOUT=False

#this is set to consider any operand of CMP (normally it should be False)
ALLCMPOP=False#True
 
# this is a directorty for internal use. Don;t change this.
KEEPD="keep/"
#set the directory path whre initial files are kept. this directory is not changed during fuzzing.

#set if dry run is required
DRYRUN=True

#set the path where new input files are created
INPUTD="data/"

#set error log in this file
ERRORS="error.log"

# set file path to read addresses of loaded libraries. This is feature is not used currently. We read the offset by running the SUT and then manually get these offsets and write them in LIBOFFSETS variable below (in the same order that names in LIBPICKLE list. 
IMAGELOAD="imageOffset.txt"


# this is the main command that is passed to run() function in runfuzzer.py

PINCMD=[PINHOME,"-tool_exit_timeout", "1","-t", PINTOOL,"-o", BBOUT,"-x", "0","-libc","0","-l",LIBTOMONITOR,"--"]

PINTNTCMD=[PINHOME,"-follow_execv","-t", PINTNT,"-filename", "inputf","-stdout","0","--"]

# IntelPT related CMD
SIMPLEPTDIR=mydir + '/../simple-pt/'
PTCMD=[SIMPLEPTDIR + '/sptcmd', '-K', '-R', '-a', '--']


### You don't have to change entries below #####

#set a minimum length (in bytes) for files that is used to control file boating
minLength=1000

#set generation count that should be skipped before we check for boating
skipGen=30

#set max frequency of BB execution that is considered.
BBMAXFREQ=10000

#set max weight to be considered for a BB
BBMAXWEIGHT=2048 

# set the impact of executing error BB on total number of BB. intuitively, it means how many BBs should be nullified by total error BBs. we calculate a negative weight which is based on the total BBs executed by an input and total error BBs detected so far. and the negative weight will be calculated dynamically by using the formula: - len(bbdict)xERRORBBPERCENTAGE/(NumErrorBB) 
ERRORBBPERCENTAGE=0.4 #(30%)
#set this flag if we want to consider BB weights, otherwise each BB have weight 1.
BBWEIGHT=True
ERRORBBON=True # this flags decides if we wnat to run error BB detection step.
# for heavy mutation
GOTSTUCK=False
# The following dictionary is used to keep all BBs with actual offsets added.
ALLBB=dict()

#some data for calculating code-coverage
cAPPBB=set()
cALLBB=set()
cPERGENBB=set()

# a set to record seen BBs across previous iterations
SEENBB=set()
TMPBBINFO=dict()
PREVBBINFO=dict() #this keeps special entries for the previous generation. It is used to delete inputs which are superceded by newer inputs in dicovering new BBs.

#a list to keep inputs that have triggered a new BB in generation. Such inputs will get a chance in the next generation as it is (no mutaiton/crossover).
SPECIALENTRY=[]
SPECIAL="special/"

# The following list has two sets as elements which contain all strings (from NAMESPICKLE files) that are used during population generations.
ALLSTRINGS=[]# this will be populated by two sets A,B. A= set of full strings from binary. B= set of individual bytes from the binary.
NOFFBYTES=True # this is a flag to ignore \xff\xff\xff\xff (which is -1) immediate.
ALLBYTES=False#True # due to certain reason, i am ignoring certain bytes, eg. \x00, \xff. if we want to check them, make is True.
# population size in each generation. Choose even number.
POPSIZE=200

# for elitist approach, set number of best inputs to go in the next generation. Make sure that POPSIZE-BESTP is multiple of 2.
BESTP=20

# number of iterations (generations) to run GA
GENNUM=1000

#set probability of selecting new inputs from special or best inputs. Higer the number (0-9), less will be the chance of selecting from Special inputs.
SELECTNUM=3

# set the number of files that will be analyzed for taintflow in new generation.
NEWTAINTFILES=80
# this is for speculating stagnation in fitness
FITMARGIN= 0
 
# Set crossover probability
PROBCROSS=0.3

#set mutation probability
PROBMUT=0.9#0.8

# set the probability of choosing MOSTCOMMON last value for a offset. Larger the value, more probability of chossing last value (default should be 8)
MOSTCOMNLAST= 6
RANDOMCOMN= False#True # this is to skip setting most common values for a offset sometimes.

# stoping condition "if found a crash, stop"
STOPONCRASH=False 

# stoping condition "if run for GENNUM, stop"

STOPOVERGENNUM= True

PTMODE=False

#some internal variables.

CRASHIN=set() #set to keep name of the file resulted ina crash.
ERRORBBAPP=set()
ERRORBBLIB=set()
ERRORBBALL=set()
GOODBB=set() # populated once during dry run on valid inputs
TEMPTRACE=[]# list of lists corresponding to bit vectors of individual traces in a single generation
BBSEENVECTOR=[] # list of BBs seen in a single generation
TEMPERRORBB=set() # contains a set of blacklisted BBs that is populated across generations
#NEWADDEDBB=0 # this is used to count newly added BBs in a generation, so that bit vectors for previous traces can be adjusted.
BBPERCENT=90
 
# temporary directory for creating new generation of inputs

TEMPDIR="datatemp/"
SPECIAL="special/" #directory to keep special inputs, i.e., crashing inputs and new BB discoverers.
INTER="inter/" # directory to combine initial inputs + special inputs to choose new inputs during population generation.

PRINTBBHIT=False
PRINTBBMISS=False
PRINTCACHESTATS=True

### Taintflow related settings and variables are here ####
# this is a dictionary to keep per input taintinfo. key=file_name, value=tuple(set(all offsets used in some CMP),dict(key=offset; value=list(concrete values of immediates in CMP)))
TAINTMAP=dict()
LEAMAP=dict() # dictionary to keep offsets for a input that were used in LEA instructions.

#this is the limit of tainted file lines that we'll read. this is to avoid reading huge files.
MAXFILELINE=200000
# flag for endianness, used for offset value extraction from the trace. if it is set, reverse string is returned.
ARCHLIL=False#True

# this dictinary keeps offsets and their immediate values that are found in all the initial inputs. key=offset, value=list(immediate values in CMP). we also use negative offsets to mark bootom offsets in a file.
MOSTCOMMON=dict()
MORECOMMON=dict() #similar to mostcommon dict, but is used to keep common offsets-values pair for later generations. this is kept seperate because MOSTCOMMON based mutation sometimes takes values that were checked in CMP inst for other possible magicbytes!!
MOSTCOMFLAG=False # flag to compute MOSTCOMMON offsets only once.
MAXOFFSET=20 #this value is used to select mostcommon offsets in file. Offsets upto this value are used for such calculation.
MINOFFSET=10 # this is to track offsets from the end of the file. so, if file size is 50 (offset 49), we write it as -1 (49-50), -2 (48-50), ... (50-MINOFFSET-50)
MAXINPUTLEN=50000 # this is the limit (50kb) on length of the input. After that len will be used in fitness calc (as denominator). 
#pintool cmd: ../../../pin -tool_exit_timeout 1 -t obj-intel64/bbcounts.so -x 20 -l libjpeg -- /usr/bin/eog esu.png

FLASK=False
