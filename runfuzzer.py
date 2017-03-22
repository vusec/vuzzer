import subprocess
import shlex
import time
import threading
from threading import Timer
import config
import pickle
import os
import operators
import random
from operator import itemgetter
import time
import shutil
import inspect
import glob
import sys
from collections import Counter
from datetime import datetime
import binascii as bina
import copy
import re
import hashlib


import gautils as gau
import mmap
import BitVector as BV
import argparse

#config.MOSTCOMFLAG=False # this is set once we compute taint for initial inputs.
libfd=open("image.offset","r+b")
libfd_mm=mmap.mmap(libfd.fileno(),0)

def get_min_file(src):
    files=os.listdir(src)
    first=False
    minsize=0
    for fl in files:
        tfl=os.path.join(src,fl)
        tsize=os.path.getsize(tfl)
        if first == False:
            minsize=tsize
            first = True
        else:
            if tsize < minsize:
                minsize=tsize
    return minsize

def check_env():
    ''' this function checks relevant environment variable that must be set before we stat our fuzzer..'''
    if os.getenv('PIN_ROOT') == None:
        gau.die("PIN_ROOT env is not set. Run export PIN_ROOT=path_to_pin_exe")
    fd1=open("/proc/sys/kernel/randomize_va_space",'r')
    b=fd1.read(1)
    fd1.close()
    if int(b) != 0:
        gau.die("ASLR is not disabled. Run: echo 0 | sudo tee /proc/sys/kernel/randomize_va_space")
    fd=open("/proc/sys/kernel/yama/ptrace_scope",'r')
    b=fd.read(1)
    fd.close()
    if int(b) != 0:
        gau.die("Pintool may not work. Run: echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope")


def run(cmd):
    print "[*] Just about to run ", cmd
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    print "[*] Run complete..\n"
    return proc.returncode

def sha1OfFile(filepath):
    with open(filepath, 'rb') as f:
        return hashlib.sha1(f.read()).hexdigest()

def bbdict(fn):
    with open(config.BBOUT,"r") as bbFD:
       bb = {}
       for ln in bbFD:
           tLine = ln.split()
           bbadr=int(tLine[0],0)
           bbfr=int(tLine[1],0)
           bb[bbadr] = bbfr
       return bb


def form_bitvector(bbdict):
    ''' This function forms bit vector for each trace and append them to config.TEMPTRACE list. '''
    newbb=0
    temp=set()
    for bbadr in bbdict:
        
        temp.add(bbadr)
        if bbadr not in config.BBSEENVECTOR:
            #added for bit vector formation
            newbb +=1
            config.BBSEENVECTOR.append(bbadr)
    tbv=BV.BitVector(size=(len(config.BBSEENVECTOR)))
    if newbb == 0:
        for el in temp:
            tbv[config.BBSEENVECTOR.index(el)]=1
        config.TEMPTRACE.append(tbv.deep_copy())
    else:
        for bvs in config.TEMPTRACE:
            bvs.pad_from_right(newbb)
        for el in temp:
            tbv[config.BBSEENVECTOR.index(el)]=1
        config.TEMPTRACE.append(tbv.deep_copy())
    del tbv

def calculate_error_bb():
    ''' this function calculates probably error handling bbs. the heuristic is:
    if a bb is appearing N% of the traces and it is not in the traces of valid inputs, it indicates a error handling bb.'''
    erfd=open("errorbb.txt",'w')
    perc=(config.BBPERCENT/100)*config.POPSIZE
    sn=len(config.BBSEENVECTOR)
    tbv=BV.BitVector(size=sn)
    tbv[-1]=1
    for i in range(sn):
        tbv=tbv>>1
        for tr in config.TEMPTRACE:
            count =0
            tt = tr & tbv
            if tt.count_bits() == 1:
                count +=1
        if count > perc and config.BBSEENVECTOR[i] not in config.GOODBB:
            config.TEMPERRORBB.add(config.BBSEENVECTOR[i])
    for bbs in config.TEMPERRORBB:
        erfd.write("0x%x\n"%(bbs,))
    erfd.close()
    del tt
    del tbv

def execute(tfl):
    bbs={}
    args=config.SUT % tfl
    runcmd=config.PINCMD+args.split(' ')
    try:
        os.unlink(config.BBOUT)
    except:
        pass
    retc = run(runcmd)
    #check if loading address was changed
    #liboffsetprev=int(config.LIBOFFSETS[1],0)
    if config.LIBNUM == 2:
        if config.BIT64 == False:
            liboffsetcur=int(libfd_mm[:10],0)
        else:
            liboffsetcur=int(libfd_mm[:],0)
        libfd_mm.seek(0)
        if liboffsetcur != int(config.LIBOFFSETS[1],0):
            #print "Load address changed!"
            gau.die("load address changed..run again!")
    # open BB trace file to get BBs
    bbs = bbdict(config.BBOUT)
    if config.CLEANOUT == True:
        gau.delete_out_file(tfl)
    return (bbs,retc)

def get_hexStr(inp):
    ''' This functions receives a hex string (0xdddddd type) and returns a string of the form \xdd\xdd..... Also, we need to take care of endianness. it it is little endian, this string needs to be reversed'''
    if len(inp[2:])%2 != 0:
        r=bina.unhexlify('0'+inp[2:])
    else:
        r= bina.unhexlify(inp[2:])
    if config.ARCHLIL==True:
        return r[::-1]
    else:
        return r
    #return bina.unhexlify('0'+inp[2:])
    #return bina.unhexlify(inp[2:])

def isNonPrintable(hexstr):
    nonprint=['\x0a','\x0d']
    if hexstr in nonprint:
        return True
    else:
        return False

def execute2(tfl,fl):
    args=config.SUT % tfl
    pargs=config.PINTNTCMD[:]
    pargs[pargs.index("inputf")]=fl
    runcmd=pargs+args.split(' ')
    #print "[*] Executing: ",runcmd 
    retc = run(runcmd)
    if config.CLEANOUT == True:
        gau.delete_out_file(tfl)
    return retc

def extract_offsetStr(offStr,hexs,fsize):
    '''Given a string of offsets, separated by comma and other offset num, this function return a tuple of offset and hex_string.'''
    offsets=offStr.split(',')
    offsets=[int(o) for o in offsets]
    if len(offsets)<5:#==1:#<5:
        ofs=offsets[0]# as this only to detect magicbytes, i assume that magicbytes are contiguous in file and thus i only consider the 1st offset.
        if ofs>fsize-config.MINOFFSET:
            ofs=ofs-fsize
        hexstr=get_hexStr(hexs)
        #raw_input("hexStr: %s"%(hexstr,))
        #raw_input("hexstr is %s"%(bina.b2a_hex(hexstr),))
        return (ofs,hexstr)
    else:
        return (-1000, offsets[:])

def get_non_empty(mat, num):
    
    ind=num
    while ind < num+5:
        if mat.group(ind) !='':
            return mat.group(ind)
        ind +=1
    return -1

def read_lea():
    '''
    we also read lea.out file to know offsets that were used in LEA instructions. There offsets are good candidates to fuzz with extreme values, like \xffffffff, \x80000000.'''
    leaFD=open("lea.out","r")
    offsets=set() # set to keep all the offsets that are used in LEA instructions.
    pat=re.compile(r"(\d+) (\w+) \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\}",re.I)
    
    for ln in leaFD:
        mat=pat.match(ln)
        try:# this is a check to see if lea entry is complete.
            rr=mat.group(6)
        except:
            continue
        tempoff=get_non_empty(mat,3)#mat.group(9)
        if tempoff == -1:
            continue
        toff=tempoff.split(',')
        toff=[int(o) for o in toff]
        if len(toff)<5:
            offsets.add(toff[0])
    return offsets.copy()




def read_taint(fpath):
    ''' This function read cmp.out file and parses it to extract offsets and coresponding values and returns a tuple(alltaint, dict).
    dictionary: with key as offset and values as a set of hex values checked for that offset in the cmp instruction. Currently, we want to extract values s.t. one of the operands of CMP instruction is imm value for this set of values.
    ADDITION: we also read lea.out file to know offsets that were used in LEA instructions. There offsets are good candidates to fuzz with extreme values, like \xffffffff, \x80000000.
    '''

    taintOff=dict()#dictionary to keep info about single tainted offsets and values.
    alltaintoff=set()#it keeps all the offsets (expluding the above case) that were used at a CMP instruction.
    fsize=os.path.getsize(fpath)
    offlimit=0
    cmpFD=open("cmp.out","r")
    # each line of the cmp.out has the following format:
    #32 reg imm 0xb640fb9d {155} {155} {155} {155} {} {} {} {} 0xc0 0xff
    #g1 g2 g3     g4        g5    g6    g7    g8  g9 g10 g11 g12 g13 g14
    # we need a regexp to parse this string.
    pat=re.compile(r"(\d+) ([a-z]+) ([a-z]+) (\w+) \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} \{([0-9,]*)\} (\w+) (\w+)",re.I)
    for ln in cmpFD:
        if offlimit>config.MAXFILELINE:
            break
        offlimit +=1
        mat=pat.match(ln)
        try:# this is a check to see if CMP entry is complete.
            rr=mat.group(14)
        except:
            continue
        
        if config.ALLCMPOP == True:
            if mat.group(5) =='' and mat.group(9) !='':
                tempoff=get_non_empty(mat,9)#mat.group(9)
                if tempoff ==-1:
                    continue
                ofs,hexstr=extract_offsetStr(tempoff,mat.group(13),fsize)
            elif mat.group(9) =='' and mat.group(5) !='':
                tempoff=get_non_empty(mat,5)#mat.group(5)
                if tempoff ==-1:
                    continue
                ofs,hexstr=extract_offsetStr(tempoff,mat.group(14),fsize)
            else:
                ofs,hexstr=(-1000,[])

            if ofs !=-1000:
                if config.ALLBYTES==True or (hexstr !='\xff\xff\xff\xff' and hexstr != '\x00'):#this is a special case
                    if ofs not in taintOff:
                        taintOff[ofs]=[hexstr]# we are going to change set to list for "last" offset checked.
                    else:
                    #if hexstr not in taintOff[ofs]:
                        if config.ALLBYTES == True or isNonPrintable(hexstr) ==False:
                            taintOff[ofs].append(hexstr)

            else:
                alltaintoff.update(set(hexstr))
        else:
            if mat.group(2) == 'imm':
                tempoff=get_non_empty(mat,9)#mat.group(9)
                if tempoff == -1:
                    continue
                ofs,hexstr=extract_offsetStr(tempoff,mat.group(13),fsize)
                if ofs !=-1000:
                    if config.ALLBYTES == True or (hexstr !='\xff\xff\xff\xff' and hexstr != '\x00'):#this is a special case
                        if ofs not in taintOff:
                            taintOff[ofs]=[hexstr]# we are going to change set to list for "last" offset checked.
                        else:
                            #if hexstr not in taintOff[ofs]:
                            if config.ALLBYTES == True or isNonPrintable(hexstr) ==False:
                                taintOff[ofs].append(hexstr)
                else:
                    #alltaintoff.update(set(offsets))
                    alltaintoff.update(set(hexstr))
            elif mat.group(3) == 'imm':
                tempoff=get_non_empty(mat,5)#mat.group(5)
                if tempoff == -1:
                    continue
                ofs,hexstr=extract_offsetStr(tempoff,mat.group(14),fsize)
            
                if ofs !=-1000:
                    if config.ALLBYTES == True or (hexstr !='\xff\xff\xff\xff' and hexstr !='\x00'):#this is a special case
                        if ofs not in taintOff:
                            taintOff[ofs]=[hexstr]# we are going to change set to list for "last" offset checked.
                        else:
                            #if hexstr not in taintOff[ofs]:
                            if config.ALLBYTES == True or isNonPrintable(hexstr) ==False:
                                taintOff[ofs].append(hexstr)

                else:
                    alltaintoff.update(set(hexstr))
            elif ((mat.group(2) == 'mem' and mat.group(3) =='mem') or (mat.group(2) == 'reg' and mat.group(3) =='reg')):
                #bylen=mat.group(1)/8
                #if bylen == 1:
                #TOFIX: I am assuming that CMPS has second operand as constant and 1st operand is the byte from the input that we want to compare with 2nd operand. We need to handle the case when these operands are swapped.
                if mat.group(5) =='' and mat.group(9) !='':

                    tempoff=get_non_empty(mat,9)#mat.group(9)
                    if tempoff ==-1:
                        continue
                    ofs,hexstr=extract_offsetStr(tempoff,mat.group(13),fsize)
                elif mat.group(9) =='' and mat.group(5) !='':
                    tempoff=get_non_empty(mat,5)#mat.group(5)
                    if tempoff ==-1:
                        continue
                    ofs,hexstr=extract_offsetStr(tempoff,mat.group(14),fsize)
                else:
                    ofs,hexstr=(-1000,[])
     
                if ofs !=-1000:
                    if config.ALLBYTES == True or (hexstr !='\xff\xff\xff\xff' and hexstr != '\x00'):#this is a special case
                        if ofs not in taintOff:
                            taintOff[ofs]=[hexstr]# we are going to change set to list for "last" offset checked.
                        else:
                            #if hexstr not in taintOff[ofs]:
                            if config.ALLBYTES == True or isNonPrintable(hexstr) ==False:
                                taintOff[ofs].append(hexstr)

                else:
                    alltaintoff.update(set(hexstr))


            else:
                tmpset=set()
                tmp1=mat.group(5)
                if len(tmp1)>0:
                    tmpset.update(tmp1.split(','))
                tmp2=mat.group(9)
                if len(tmp2)>0:
                    tmpset.update(tmp2.split(','))
                alltaintoff.update([int(o) for o in tmpset])
                #alltaintoff.update(tmp1.split(','),tmp2.split(','))
                #alltaintoff=set([int(o) for o in alltaintoff])
    cmpFD.close()
    todel=set()
    for el in alltaintoff:
        if el>fsize-config.MINOFFSET:
            todel.add(el)
    for el in todel:
        alltaintoff.remove(el)
        #print '*',el
        alltaintoff.add(el-fsize)

    #alltaintoff.difference_update(taintOff)
    #print alltaintoff, taintOff
    
    return (alltaintoff,taintOff)

     

def get_taint(dirin):
    ''' This function is used to get taintflow for each CMP instruction to find which offsets in the input are used at the instructions. It also gets the values used in the CMP.'''
    print "[*] starting taintflow calculation."
    files=os.listdir(dirin)
    #taintmap=dict()#this is a dictionary to keep taintmap of each input file. Key is the input file name and value is a tuple returned by read_taint, wherein 1st element is a set of all offsets used in cmp and 2nd elment is a dictionary with key a offset and value is a set of values at that offsetthat were found in CMP instructions.
    #mostcommon=dict()# this dictionary keeps offsets which are common across all the inputs with same value set. 
    for fl in files:
        if fl in config.TAINTMAP:
            continue
        pfl=os.path.join(dirin,fl)
        rcode=execute2(pfl,fl)
        if rcode ==255:
            continue
            gau.die("pintool terminated with error 255 on input %s"%(pfl,))
        config.TAINTMAP[fl]=read_taint(pfl)
        config.LEAMAP[fl]=read_lea()
        #print config.TAINTMAP[fl][1]
        #raw_input("press key..")
    if config.MOSTCOMFLAG==False:
        print "computing MOSTCOM calculation..."
        for k1,v1 in config.TAINTMAP.iteritems():
            for off1,vset1 in v1[1].iteritems():
                tag=True
                if off1 > config.MAXOFFSET:
                    config.TAINTMAP[k1][0].add(off1)
                    #print "[==] ",k1,off1
                    continue
                    
                    
                    
                for k2,v2 in config.TAINTMAP.iteritems():
                    if off1 not in v2[1]:
                        config.TAINTMAP[k1][0].add(off1)
                        #print k2,v2[1]
                        tag=False
                        break
                    #print "passed..", off1
                    if len(set(vset1) & set(v2[1][off1]))==0:#set(vset1) != set(v2[off1])
                        print k1, k2, off1, set(vset1), set(v2[1][off1])
                        config.TAINTMAP[k1][0].add(off1)
                        tag=False
                        break
                    #print "passed set", vset1
                if tag==True:
                    config.MOSTCOMMON[off1]=vset1[:]
                    #print "[++]",config.MOSTCOMMON[off1]
            break # we just want to take one input and check if all the offsets in other inputs have commonality.
    else:
        print "computing MORECOM calculation..."
        for k1,v1 in config.TAINTMAP.iteritems():
            for off1,vset1 in v1[1].iteritems():
                tag=True
                #if off1 > config.MAXOFFSET:
                    #print k1,off1
                #    continue
                for k2,v2 in config.TAINTMAP.iteritems():
                    if off1 not in v2[1]:
                        config.TAINTMAP[k1][0].add(off1)
                        #print k2,v2[1]
                        tag=False
                        break
                    #print "passed..", off1
                    if len(set(vset1) ^ set(v2[1][off1]))>3:#vset1 != v2[1][off1]:
                        print k2, vset1, v2[1][off1]
                        config.TAINTMAP[k1][0].add(off1)
                        tag=False
                        break
                    #print "passed set", vset1
                if tag==True:
                    config.MORECOMMON[off1]=vset1[:]
                    #print config.MOSTCOMMON[off1]
            break # we just want to take one input and check if all the offsets in other inputs have commonality.
    
    print "[*] taintflow finished."     

def dry_run():
    ''' this function executes the initial test set to determine error handling BBs in the SUT. Such BBs are given zero weights during actual fuzzing.
'''
    print "[*] Starting dry run now..."
    tempbad=[]
    dfiles=os.listdir(config.INITIALD)
    if len(dfiles) <3:
        gau.die("not sufficient initial files")

    for fl in dfiles:
        tfl=os.path.join(config.INITIALD,fl)
        try:
            f=open(tfl, 'r')
            f.close()
        except:
            gau.die("can not open our own input %s!"%(tfl,))
        (bbs,retc)=execute(tfl)
        if retc < 0:
            gau.die("looks like we already got a crash!!")
        config.GOODBB |= set(bbs.keys())
    print "[*] Finished good inputs (%d)"%(len(config.GOODBB),)
    #now lets run SUT of probably invalid files. For that we need to create them first.
    print "[*] Starting bad inputs.."
    lp=0
    badbb=set()
    while lp <2:
        try:
                shutil.rmtree(config.INPUTD)
        except OSError:
                pass

        os.mkdir(config.INPUTD)
        gau.create_files_dry(30)
        dfiles=os.listdir(config.INPUTD)
        for fl in dfiles:
            tfl=os.path.join(config.INPUTD,fl)
            (bbs,retc)=execute(tfl)
            if retc < 0:
                gau.die("looks like we already got a crash!!")
            tempbad.append(set(bbs.keys()) - config.GOODBB)
            
        tempcomn=set(tempbad[0])
        for di in tempbad:
            tempcomn.intersection_update(set(di))
        badbb.update(tempcomn)
        lp +=1
    #else:
    #  tempcomn = set()
    ###print "[*] finished bad inputs (%d)"%(len(tempbad),)
    config.ERRORBBALL=badbb.copy()
    print "[*] finished common BB. TOtal such BB: %d"%(len(badbb),)
    for ebb in config.ERRORBBALL:
        print "error bb: 0x%x"%(ebb,)
    time.sleep(5)
    if config.LIBNUM == 2:
        baseadr=config.LIBOFFSETS[1]
        for ele in tempcomn:
            if ele < baseadr:
                config.ERRORBBAPP.add(ele)
            else:
                config.ERRORBBLIB.add(ele-baseadr)
                         
    del tempbad
    del badbb
    #del tempgood
    return len(config.GOODBB),len(config.ERRORBBALL)
    
def run_error_bb(pt):
    print "[*] Starting run_error_bb." 
    files = os.listdir(config.INPUTD)
    for fl in files:
        tfl=os.path.join(config.INPUTD,fl)
        (bbs,retc)=execute(tfl)
        #if retc < 0:
        #    print "[*] crashed while executing %s"%(fl,)
        #    gau.die("Bye...")
        form_bitvector(bbs)
    calculate_error_bb()
def copy_files(src, dest,num):
        files =random.sample(os.listdir(src),num)
        for fl in files:
                tfl=os.path.join(src,fl)
                shutil.copy(tfl,dest)
def conditional_copy_files(src, dest,num):
    #count = 0;
    #tempbuf=set()
    flist=os.listdir(src)
    # we need to handle the case wherein newly added files in SPECIAL are less than the num. in this case, we only copy these newly added files to dest.
    extra=set(flist)-set(config.TAINTMAP)
    if len(extra) == 0:
        return -1
    if len(extra)<num:
        for fl in extra:
            tfl=os.path.join(src,fl)
            shutil.copy(tfl,dest)
        return 0
    else:
        tlist=random.sample(list(extra),num)
        for fl in tlist:
            tfl=os.path.join(src,fl)
            shutil.copy(tfl,dest)
        return 0

    #while count <num:
    #    fl =random.choice(os.listdir(src))
    #    if fl not in config.TAINTMAP and fl not in tempbuf:
    #        tempbuf.add(fl)
    #        count +=1
    #        tfl=os.path.join(src,fl)
    #        shutil.copy(tfl,dest)
    #del tempbuf

def main():
    check_env()
    ## parse the arguments #########
    parser = argparse.ArgumentParser(description='VUzzer options')
    parser.add_argument('-s','--sut', help='SUT commandline',required=True)
    parser.add_argument('-i','--inputd', help='seed input directory (relative path)',required=True)
    parser.add_argument('-w','--weight', help='path of the pickle file(s) for BB wieghts (separated by comma, in case there are two) ',required=True)
    parser.add_argument('-n','--name', help='Path of the pickle file(s) containing strings from CMP inst (separated by comma if there are two).',required=True)
    parser.add_argument('-l','--libnum', help='Nunber of binaries to monitor (only application or used libraries)',required=False, default=1)
    parser.add_argument('-o','--offsets',help='base-address of application and library (if used), separated by comma', required=False, default='0x00000000')
    parser.add_argument('-b','--libname',help='library name to monitor',required=False, default='')
    args = parser.parse_args()
    config.SUT=args.sut
    config.INITIALD=os.path.join(config.INITIALD, args.inputd)
    config.LIBNUM=int(args.libnum)
    config.LIBTOMONITOR=args.libname
    config.LIBPICKLE=[w for w in args.weight.split(',')]
    config.NAMESPICKLE=[n for n in args.name.split(',')]
    config.LIBOFFSETS=[o for o in args.offsets.split(',')]
    ih=config.PINCMD.index("#") # this is just to find the index of the placeholder in PINCMD list to replace it with the libname
    config.PINCMD[ih]=args.libname


    ###################################

    config.minLength=get_min_file(config.INITIALD)
    try:
        shutil.rmtree(config.KEEPD)
    except OSError:
        pass
    os.mkdir(config.KEEPD)
    
    try:
        os.mkdir("outd")
    except OSError:
        pass
    
    try:
        os.mkdir("outd/crashInputs")
    except OSError:
        gau.emptyDir("outd/crashInputs")

    crashHash=[]
    try:
        os.mkdir(config.SPECIAL)
    except OSError:
        gau.emptyDir(config.SPECIAL)
    
    try:
        os.mkdir(config.INTER)
    except OSError:
        gau.emptyDir(config.INTER)
   
    ###### open names pickle files
    gau.prepareBBOffsets()
    if config.PTMODE:
        pt = simplept.simplept()
    else:
        pt = None
    if config.ERRORBBON==True:
        gbb,bbb=dry_run()
    else:
        gbb=0
   # gau.die("dry run over..")
    import timing
    #selftest()
    noprogress=0
    currentfit=0
    lastfit=0
    
    config.CRASHIN.clear()
    stat=open("stats.log",'w')
    stat.write("**** Fuzzing started at: %s ****\n"%(datetime.now().isoformat('+'),))
    stat.write("**** Initial BB for seed inputs: %d ****\n"%(gbb,))
    stat.flush()
    os.fsync(stat.fileno())
    stat.write("Genaration\t MINfit\t MAXfit\t AVGfit MINlen\t Maxlen\t AVGlen\t #BB\t AppCov\t AllCov\n")
    stat.flush()
    os.fsync(stat.fileno())
    starttime=time.clock()
    allnodes = set()
    alledges = set()
    try:
        shutil.rmtree(config.INPUTD)
    except OSError:
        pass
    shutil.copytree(config.INITIALD,config.INPUTD)
    # fisrt we get taint of the intial inputs
    get_taint(config.INITIALD)
    print "MOst common offsets and values:", config.MOSTCOMMON
    #gg=raw_input("press enter to continue..")
    config.MOSTCOMFLAG=True
    crashhappend=False
    filest = os.listdir(config.INPUTD)
    filenum=len(filest)
    if filenum < config.POPSIZE:
        gau.create_files(config.POPSIZE - filenum)
    
    if len(os.listdir(config.INPUTD)) != config.POPSIZE:
        gau.die("something went wrong. number of files is not right!")

    efd=open(config.ERRORS,"w")
    gau.prepareBBOffsets()
    writecache = True
    genran=0
    bbslide=10 # this is used to call run_error_BB() functions
    keepslide=3
    keepfilenum=config.BESTP
    while True:
        print "[**] Generation %d\n***********"%(genran,)
        del config.SPECIALENTRY[:]
        del config.TEMPTRACE[:]
        del config.BBSEENVECTOR[:]
        config.SEENBB.clear()
        config.TMPBBINFO.clear()
        config.TMPBBINFO.update(config.PREVBBINFO)
        
        fitnes=dict()
        execs=0
        config.cPERGENBB.clear()
        config.GOTSTUCK=False
 
        if config.ERRORBBON == True:
            if genran > config.GENNUM/5:
                bbslide = max(bbslide,config.GENNUM/20)
                keepslide=max(keepslide,config.GENNUM/100)
                keepfilenum=keepfilenum/2
        #config.cPERGENBB.clear()
        #config.GOTSTUCK=False
            if 0< genran < config.GENNUM/5 and genran%keepslide == 0:
                copy_files(config.INPUTD,config.KEEPD,keepfilenum)
                
        #lets find out some of the error handling BBs
            if  genran >20 and genran%bbslide==0:
                stat.write("\n**** Error BB cal started ****\n")
                stat.flush()
                os.fsync(stat.fileno())
                run_error_bb(pt)
                copy_files(config.KEEPD,config.INPUTD,len(os.listdir(config.KEEPD))*1/10)
            #copy_files(config.INITIALD,config.INPUTD,1)
        files=os.listdir(config.INPUTD)
        for fl in files:
                tfl=os.path.join(config.INPUTD,fl)
                iln=os.path.getsize(tfl)
                args = (config.SUT % tfl).split(' ')
                progname = os.path.basename(args[0])
                #print ''
                #print 'Input file sha1:', sha1OfFile(tfl)
                #print 'Going to call:', ' '.join(args)
                (bbs,retc)=execute(tfl)
                if config.BBWEIGHT == True:
                    fitnes[fl]=gau.fitnesCal2(bbs,fl,iln)
                else:
                    fitnes[fl]=gau.fitnesNoWeight(bbs,fl,iln)

                execs+=1
                #print "** %s: %d"%(fl,fitnes[fl])
                if retc < 0 and retc != -2:
                    print "[*]Error code is %d"%(retc,)
                    efd.write("%s: %d\n"%(tfl, retc))
                    efd.flush()
                    os.fsync(efd)
                    tmpHash=sha1OfFile(config.CRASHFILE)
                    if tmpHash not in crashHash:
                            crashHash.append(tmpHash)
                            tnow=datetime.now().isoformat().replace(":","-")
                            nf="%s-%s.%s"%(progname,tnow,gau.splitFilename(fl)[1])
                            npath=os.path.join("outd/crashInputs",nf)
                            shutil.copyfile(tfl,npath)
                            shutil.copy(tfl,config.SPECIAL)
                            config.CRASHIN.add(fl)
                    if config.STOPONCRASH == True:
                        #efd.close()
                        crashhappend=True
                        break
        fitscore=[v for k,v in fitnes.items()]
        maxfit=max(fitscore)
        avefit=sum(fitscore)/len(fitscore)
        mnlen,mxlen,avlen=gau.getFileMinMax(config.INPUTD)
        print "[*] Done with all input in Gen, starting SPECIAL. \n"
        #### copy special inputs in SPECIAL directory and update coverage info ###
        spinputs=os.listdir(config.SPECIAL)
        for sfl in spinputs:
                if sfl in config.PREVBBINFO and sfl not in config.TMPBBINFO:
                        tpath=os.path.join(config.SPECIAL,sfl)
                        os.remove(tpath)
                        if sfl in config.TAINTMAP:
                            del config.TAINTMAP[sfl]
        config.PREVBBINFO=copy.deepcopy(config.TMPBBINFO)
        spinputs=os.listdir(config.SPECIAL)
        for inc in config.TMPBBINFO:
                config.SPECIALENTRY.append(inc)
                if inc not in spinputs:
                        incp=os.path.join(config.INPUTD,inc)
                        shutil.copy(incp,config.SPECIAL)
                        #del fitnes[incp]
        appcov,allcov=gau.calculateCov()
        stat.write("\t%d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\t %d\n"%(genran,min(fitscore),maxfit,avefit,mnlen,mxlen,avlen,len(config.cPERGENBB),appcov,allcov))
        stat.flush()
        os.fsync(stat.fileno())
        print "[*] Wrote to stat.log\n"
        if crashhappend == True:
            break
        #lets find out some of the error handling BBs
        #if genran >20 and genran%5==0:
         #   run_error_bb(pt)
        genran += 1
        #this part is to get initial fitness that will be used to determine if fuzzer got stuck.
        lastfit=currentfit
        currentfit=maxfit
        if currentfit==lastfit:#lastfit-config.FITMARGIN < currentfit < lastfit+config.FITMARGIN:
            noprogress +=1
        else:
            noprogress =0
        if noprogress > 20:
            config.GOTSTUCK=True
            stat.write("Heavy mutate happens now..\n")
            noprogress =0
        if (genran >= config.GENNUM) and (config.STOPOVERGENNUM == True):
            break
        # copy inputs to SPECIAL folder (if they do not yet included in this folder
        #spinputs=os.listdir(config.SPECIAL)
        #for sfl in spinputs:
        #        if sfl in config.PREVBBINFO and sfl not in config.TMPBBINFO:
        #                tpath=os.path.join(config.SPECIAL,sfl)
        #                os.remove(tpath)
        #config.PREVBBINFO=copy.deepcopy(config.TMPBBINFO)
        #spinputs=os.listdir(config.SPECIAL)
        #for inc in config.TMPBBINFO:
        #        config.SPECIALENTRY.append(inc)
        #        if inc not in spinputs:
        #                incp=os.path.join(config.INPUTD,inc)
        #                shutil.copy(incp,config.SPECIAL)
        #                #del fitnes[incp]
        if len(os.listdir(config.SPECIAL))>0:
            if len(os.listdir(config.SPECIAL))<config.NEWTAINTFILES:
                get_taint(config.SPECIAL)
            else:
                try:
                    os.mkdir("outd/tainttemp")
                except OSError:
                    gau.emptyDir("outd/tainttemp")
                if conditional_copy_files(config.SPECIAL,"outd/tainttemp",config.NEWTAINTFILES) == 0:
                    get_taint("outd/tainttemp")
            #print "MOst common offsets and values:", config.MOSTCOMMON
            #gg=raw_input("press any key to continue..")
        print "[*] Going for new generation creation.\n" 
        gau.createNextGeneration3(fitnes,genran)
        #raw_input("press any key...")

    efd.close()
    stat.close()
    libfd_mm.close()
    libfd.close()
    endtime=time.clock()
    
    print "[**] Totol time %f sec."%(endtime-starttime,)
    print "[**] Fuzzing done. Check %s to see if there were crashes.."%(config.ERRORS,)
    

if __name__ == '__main__':
    

    fuzzthread = threading.Thread(target = main)

    fuzzthread.start()

    if config.FLASK:

        socketio.run(app, host="0.0.0.0", port=5000)
