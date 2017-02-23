
/*
 PIN Tool to find all basic blocks a program executes during fuzzing by VYFuzzer.
  Code based on examples from PIN documentation.
*/


#include <pin.H>
#include <stdio.h>
#include <set>
#include <map>
#include <iostream>
#include <unistd.h>
#include <sstream>
#include <string>
#include <vector>
#include <utility>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <cstring>
#define FILEPATH "image.offset"
#define CRASHFILE "crash.bin"

using namespace std;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "bbcount.out", "specify output file name");
KNOB<UINT32> KnobLibC(KNOB_MODE_WRITEONCE, "pintool",
			 "libc", "0", "if you want to monitor libc BB");
KNOB<UINT32> KnobTimeout(KNOB_MODE_WRITEONCE, "pintool",
			 "x", "10000", "specify timeout in miliseconds");
KNOB<string> KnobXLibraries(KNOB_MODE_WRITEONCE, "pintool",
    "l", "", "specify shared lobraries to be monitored, separated by comma (no spaces)");

static FILE* trace;
static FILE* offsets;
static int ioffset;
static char *offsetmap;
off_t sz;
//static map<long unsigned int, int> bbcount;
//static pair<map<long unsigned int, int>::iterator, bool> ret;
static map<ADDRINT, unsigned int> bbcount;
static pair<map<ADDRINT, unsigned int>::iterator, bool> ret;
PIN_THREAD_UID threadUid;
static vector<pair<ADDRINT,ADDRINT> > allAddr;
static vector<string> libNames;
static FILE* crashFD;
#define LAST_EXECUTED_BB 10  
ADDRINT LastExecutedBB[LAST_EXECUTED_BB]={};  
UINT32 LastExecutedPosBB=0;
#define LAST_EXECUTED_Rtn 5  
ADDRINT LastExecutedRtn[LAST_EXECUTED_Rtn]={};  
UINT32 LastExecutedPosRtn=0;


//catching excpetions
//SIGNAL_INTERCEPT_CALLBACK 
//EXCEPT_HANDLING_RESULT ExceptionHandling(THREADID tid, EXCEPTION_INFO *pExceptInfo, PHYSICAL_CONTEXT *pPhysCtxt, VOID *v)
//VOID ExceptionHandling(THREADID threadIndex, CONTEXT_CHANGE_REASON reason, const CONTEXT *from, CONTEXT *to, INT32 info, VOID *v)
BOOL ExceptionHandling(THREADID tid, INT32 sig, CONTEXT *ctxt, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v) 
{
  UINT32 i;
  crashFD=fopen(CRASHFILE,"w");
  fprintf(crashFD,"%d",sig);
  //fprintf(crashFD,"%p",(void *) PIN_GetExceptionAddress(pExceptInfo));
  //fprintf(crashFD,"%p",(void *) PIN_GetContextReg(ctxt,REG_INST_PTR));  	
  for(i=0;i<LAST_EXECUTED_BB;i++)
  {

    fprintf(crashFD,"%p",(void *)LastExecutedBB[LastExecutedPosBB]);
    LastExecutedPosBB = (LastExecutedPosBB+1)%LAST_EXECUTED_BB;
  }
  for(i=0;i<LAST_EXECUTED_Rtn;i++)
  {
    fprintf(crashFD,"%p",(void *)LastExecutedRtn[LastExecutedPosRtn]);
    LastExecutedPosRtn = (LastExecutedPosRtn+1)%LAST_EXECUTED_Rtn;
  }
  fclose(crashFD);
  return TRUE;
  //return EHR_CONTINUE_SEARCH;
}

VOID call_direct(ADDRINT target)
{
  LastExecutedRtn[LastExecutedPosRtn]= target;
  LastExecutedPosRtn = (LastExecutedPosRtn+1)% LAST_EXECUTED_Rtn;
}

VOID call_indirect(ADDRINT target, BOOL taken)
{
  if (!taken) return;
  LastExecutedRtn[LastExecutedPosRtn]= target;
  LastExecutedPosRtn = (LastExecutedPosRtn+1)% LAST_EXECUTED_Rtn;
}


VOID ImageLoad(IMG img, VOID *v)
{
  if(IMG_IsMainExecutable(img))
    {
      //cout<<"[*]adding main executable addresses at"<<StringFromAddrint(IMG_LoadOffset(img))<<endl;
      fprintf(offsets, "Main: %s\n",StringFromAddrint(IMG_LoadOffset(img)).c_str());
      fflush(offsets);
      allAddr.push_back(std::make_pair(IMG_LowAddress(img), IMG_HighAddress(img)));
	}
  else
    {
      //cout<<"[*] "<<IMG_Name(img)<< "is loaded...at offset"<<StringFromAddrint(IMG_LoadOffset(img))<<endl;
      // lets check for libc monitoring first
        if (KnobLibC.Value() > 0)
        {
            if (IMG_Name(img).find("libc.")!=std::string::npos)
	      allAddr.push_back(std::make_pair(IMG_LowAddress(img), IMG_HighAddress(img)));
        }
      for (vector<string>::iterator it=libNames.begin();it !=libNames.end();++it)
	{
	  if (IMG_Name(img).find(*it)!=std::string::npos)
	    {
	      //cout<<"[*] "<<IMG_Name(img)<< "is being added."<<endl;
	      fprintf(offsets, "%s: %s\n",IMG_Name(img).c_str(),StringFromAddrint(IMG_LoadOffset(img)).c_str());
	      std::memcpy(offsetmap,StringFromAddrint(IMG_LoadOffset(img)).c_str(),18);
	      fflush(offsets);
	      allAddr.push_back(std::make_pair(IMG_LowAddress(img), IMG_HighAddress(img)));
		}
	}
    }
}

BOOL isMonitoredAddress(ADDRINT bb)
{
  for(vector<pair<ADDRINT,ADDRINT> >::iterator it=allAddr.begin();it!=allAddr.end();++it)
    {
      if ((bb >= (*it).first )&&(bb <= (*it).second)) return true;
    }
  return false;
}

VOID PIN_FAST_ANALYSIS_CALL rememberBlock(ADDRINT bbl)
{
  bbcount[bbl]=bbcount[bbl]+1;
   
}

VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
      if(isMonitoredAddress(BBL_Address(bbl)))
	{
	  /* Things related to stack hash/crash fingerprints */
	  LastExecutedBB[LastExecutedPosBB]= BBL_Address(bbl);
	  LastExecutedPosBB = (LastExecutedPosBB+1)% LAST_EXECUTED_BB;
	  INS tail = BBL_InsTail(bbl);
	  if( INS_IsCall(tail) )
	    {
	      if( INS_IsDirectBranchOrCall(tail))
		{
		  ADDRINT target = INS_DirectBranchOrCallTargetAddress(tail);
		  INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(call_direct), IARG_ADDRINT, target, IARG_END);
		}
	      else
		{
		  INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(call_indirect), IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
		}
	    }
	  /* stack hask ends here. */

	  BBL_InsertCall(bbl, IPOINT_ANYWHERE, AFUNPTR(rememberBlock), IARG_FAST_ANALYSIS_CALL, IARG_ADDRINT, BBL_Address(bbl), IARG_END);
	}
    }
}

static VOID TimeoutF(VOID * arg)
{
  // this function is called in a separate threat to exit the applications after n seconds
  //cout<<"[*] In the thread now..."<<endl;
  sleep(KnobTimeout.Value());
  //cout<<"[*]Going to kill application.."<<endl;
  PIN_ExitApplication(0);
  /*while(true)
    {
      if (PIN_IsProcessExiting())
	{
	  PIN_ExitThread(0);
	}
    }
    return 0;*/
  //cout<<"[*] Application is killed..Exiting thread now."<<endl;
  PIN_ExitThread(0);

}


VOID Fini(INT32 code, VOID *v)
{
    /*
    set<unsigned int>::iterator i;
    for(i = setKnownBlocks.begin(); i != setKnownBlocks.end(); ++i)
    {
        fprintf(trace, "%p\n", *i);
    }
    */
  //if(ret.second == true)
  map<ADDRINT,unsigned int>::iterator bb;
  for (bb=bbcount.begin();bb!=bbcount.end();++bb)
    {
      fprintf(trace, "%p %u\n", (void *)bb->first, bb->second);
    //fflush(trace);
      
    }
  fclose(trace);
  fclose(offsets);
  munmap(offsetmap, 18);
  close(ioffset);
}


/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool counts the number of basic block executed with their frequencies" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}



int main(int argc, char * argv[])
{
 // Initialize symbol processing
    PIN_InitSymbols();

    offsets = fopen("imageOffset.txt", "w");
    //open file and mmap it to write image load address
    ioffset = open(FILEPATH, O_RDWR);
    if (ioffset == -1)
      {
	perror("Error opening file for writing");
	exit(0);
      }
    //sz = lseek(ioffset, 0, SEEK_END);
     //printf("file size %ld\n",(long int)sz);
     //lseek(ioffset, -sz, SEEK_END);
     offsetmap = (char*)mmap(0, 18, PROT_READ | PROT_WRITE, MAP_SHARED, ioffset, 0);
     if (offsetmap == MAP_FAILED) {
	close(ioffset);
	printf("Error mmapping the file");
	//perror("Error mmapping the file");
	exit(0);
     }

  PIN_THREAD_UID threadUid;
  //THREADID threadId;
 
    
  if (PIN_Init(argc, argv)) return Usage();
    trace = fopen(KnobOutputFile.Value().c_str(), "w");
    TRACE_AddInstrumentFunction(Trace, 0);
    /* lets add signal intercept for signal 1, 6, and 11. */
    INT32 signals[3]={1,6,11};
    for (INT32 sig=0;sig<3;sig++)
      {
	PIN_InterceptSignal(signals[sig], ExceptionHandling, NULL);
        PIN_UnblockSignal(sig, TRUE);
      }
    if (!KnobXLibraries.Value().empty())
      {
	stringstream libs(KnobXLibraries.Value().c_str());
	while(libs.good())
	  {
	    string temp;
	    getline(libs,temp,',');
	    libNames.push_back(temp);
	  }
      }
// Register ImageLoad to be called when an image is loaded
    IMG_AddInstrumentFunction(ImageLoad, 0);

    PIN_AddFiniFunction(Fini, 0);
    //PIN_AddFiniUnlockedFunction(Fini,0); 	
    //sleep(5);
    cout<<"Starting the app now..." << endl;
	if (KnobTimeout.Value() > 0)
    	PIN_SpawnInternalThread(TimeoutF,0,0,&threadUid);
    PIN_StartProgram();
    //cout << "done.." << endl;
    //sleep(10);
    //PIN_ExitApplication(0);
    
    return 0;
}

// end
