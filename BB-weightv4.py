# -----------------------------------------------------------------------
# This script computes a weight value for each basis block of each functions. the algorithm is:
# 1. for each outgoing edge (i->j) of a BB i, assign a equal probability Eij, i.e. Eij= 1/n for a "n edges" BB.
# 2. assign root BB a weight of 1 (this is always reachable).
# 3. for each BB j, its weight is: W(j) = SUM (over i \in Pred(j)) W(i)*Eij
# after completion, it creates a pickle file that contains weights of BBs.
##Addintion: it also scans each function to find CMD instruction and check if it has some byte to compare with. All such bytes are saved in a pickle file that will be used to mutate inputs.


import idaapi
import idautils
import idc
#from idaapi import *
#from idautils import *
#from idc import *
from collections import deque
#import json
import timeit
import pickle
import string

## global definitions ##
edges=dict()## dictionary to keep edge's weights. key=(srcBB,dstBB), value=weight
weight=dict() ## dictionary to keep weight of a BB. key=BB_startAddr, value=(weight, BB_endAddr)
fweight=dict()## similar to weight. only value is replaced by (1.0/weight, BB_endAddr)
fCount=0

def findCMPopnds():
    ''' This funstion scans whole binary to find CMP instruction and get its operand which is immediate. Function returns a set of such values.
    '''
    cmpl=['cmp','CMP']
    names=set()
    result1=set()#contains full strings as they appear in the instruction 
    result2=set()#contains bytes of strings in instruction
    # For each of the segments
    for seg_ea in Segments():
        for head in Heads(seg_ea, SegEnd(seg_ea)):
            if isCode(GetFlags(head)):
                mnem = GetMnem(head)
                #print mnem
                if mnem in cmpl:
                    for i in range(2):
                        if GetOpType(head,i)==5:
                            names.add(GetOpnd(head,i))
                        
    for el in names:
        tm=el.rstrip('h')
        if not all(c in string.hexdigits for c in tm):
            continue # strange case: sometimes ida returns not immediate!!
        if len(tm)%2 !=0:
            tm='0'+tm
        whx=''
        for i in xrange(0,len(tm),2):
            #hx=chr('\\x'+tm[i:i+2]
            hx=chr(int(tm[i:i+2],16))
            result2.add(hx)
            whx=whx+hx
        result1.add(whx)
    #for e in result:
    #print e
    result1.difference_update(result2)
    print result1, result2
    return [result1,result2]

def get_children(BB):
    '''
    This function returns a list of BB ids which are children (transitive) of given BB.
    '''
    print "[*] finding childrens of BB: %x"%(BB.startEA,)
    child=[]
    tmp=deque([])
    tmpShadow=deque([])
    #visited=[]
    for sbb in BB.succs():
        tmp.append(sbb)
        tmpShadow.append(sbb.startEA)
    if len(tmp) == 0:
        return child
    while len(tmp)>0:
        cur=tmp.popleft()
        tmpShadow.popleft()
        if cur.startEA not in child:
            
            child.append(cur.startEA)
        for cbbs in cur.succs():
            if (cbbs.startEA not in child) and  (cbbs.startEA not in tmpShadow):
                
                tmp.append(cbbs)    
                tmpShadow.append(cbbs.startEA)
    del tmp
    del tmpShadow
    return child



def calculate_weight(func, fAddr):


    ''' This function calculates weight for each BB, in the given function func.
    '''
    # We start by iterating all BBs and assigning weights to each outgoing edges.
    # we assign a weight 0 to loopback edge because it does not point (i.e., leading) to "new" BB.
    edges.clear()
    temp = deque([]) # working queue
    rootFound= False
    visited=[] # list of BBid that are visited (weight calculated)
    shadow=[]
    noorphan=True
    for block in func:
        pLen=len(list(block.succs()))
        if pLen == 0: # exit BB
            continue
        eProb=1.0/pLen #probability of each outgoing edge
        #print "probability = %3.1f"%(eProb,), eProb
        for succBB in block.succs():
            if (succBB.startEA <= block.startEA) and (len(list(succBB.preds()))>1):
                #this is for backedge. this is not entirely correct as BB which are shared or are at lower
                #addresses are tagged as having zero value!! TO FIX.
                edges[(block.startEA,succBB.startEA)]=1.0
            else:
                edges[(block.startEA,succBB.startEA)]=eProb
    print "[*] Finished edge probability calculation"
    #for edg in edges:
        #print " %x -> %x: %3.1f "%(edg[0],edg[1],edges[edg])
    # lets find the root BB
    #orphanage=[]#home for orphan BBs
    orphID=[]
    for block in func:
        if len(list(block.preds())) == 0:
        #Note: this only check was not working as there are orphan BB in code. Really!!!

            if block.startEA == fAddr:
                rootFound=True
                root = block
            else:
                if rootFound==True:
                    noorphan=False
                    break
                pass
    #now, all the BBs should be children of root node and those that are not children are orphans. This check is required only if we have orphans.
    if noorphan == False:
        rch=get_children(root)
        rch.append(fAddr)# add root also as a non-orphan BB
        for blk in func:
            if blk.startEA not in rch:
                weight[blk.startEA]=(1.0,blk.endEA)
                visited.append(blk.id)
                orphID.append(blk.id)
        #print "[*] orphanage calculation done."
        del rch
    if rootFound==True:
        #print "[*] found root BB at %x"%(root.startEA,)
        weight[root.startEA] = (1.0,root.endEA)
        visited.append(root.id)
        print "[*] Root found. Starting weight calculation."
        for sBlock in root.succs():
            #if sBlock.id not in shadow:
            #print "Pushing successor %x"%(sBlock.startEA,)
            temp.append(sBlock)
            shadow.append(sBlock.id)
        loop=dict()# this is a temp dictionary to avoid get_children() call everytime a BB is analysed.
        while len(temp) > 0:
            current=temp.popleft()
            shadow.remove(current.id)
            print "current: %x"%(current.startEA,)
            if current.id not in loop:
                loop[current.id]=[]
            # we check for orphan BB and give them a lower score
            # by construction and assumptions, this case should not hit!
            if current.id in orphID:
                #weight[current.startEA]=(0.5,current.endEA)
                #visited.append(current.id)
                continue

            tempSum=0.0
            stillNot=False
            chCalculated=False
            for pb in current.preds():
                #print "[*] pred of current %x"%(pb.startEA,)
                if pb.id not in visited:
                    if edges[(pb.startEA,current.startEA)]==0.0:
                        weight[pb.startEA]=(0.5,pb.endEA)
                        #artificial insertion
                        #print "artificial insertion branch"
                        continue
                    if pb.id not in [k[0] for k in loop[current.id]]:
                        if chCalculated == False:
                            chCurrent=get_children(current)
                            chCalculated=True
                        if pb.startEA in chCurrent:
                            # this BB is in a loop. we give less score to such BB
                            weight[pb.startEA]=(0.5,pb.endEA)
                            loop[current.id].append((pb.id,True))
                            #print "loop branch"
                            continue
                        else:
                            loop[current.id].append((pb.id,False))
                    else:
                        if (pb.id,True) in loop[current.id]:
                            weight[pb.startEA]=(0.5,pb.endEA)
                            continue
                            
                    #print "not pred %x"%(pb.startEA,)
                    if current.id not in shadow:
                        temp.append(current)
                        #print "pushed back %x"%(current.startEA,)
                        shadow.append(current.id)
                    stillNot=True
                    break
            if stillNot == False:
                # as we sure to get weight for current, we push its successors
                for sb in current.succs():
                    if sb.id in visited:
                        continue
                    if sb.id not in shadow:
                        temp.append(sb)
                        shadow.append(sb.id)
                for pb in current.preds():
                    tempSum = tempSum+ (weight[pb.startEA][0]*edges[(pb.startEA,current.startEA)])
                weight[current.startEA] = (tempSum,current.endEA)
                visited.append(current.id)
                del loop[current.id]
                print "completed %x"%(current.startEA,)
                #print "remaining..."
                #for bs in temp:
                    #print "\t %x"%(bs.startEA,)

def analysis():
    global fCount
    all_funcs = idautils.Functions()
    for f in all_funcs:
        fflags=idc.GetFunctionFlags(f)
        if (fflags & FUNC_LIB) or (fflags & FUNC_THUNK):
            continue
        fCount = fCount+1
        print "In %s:\n"%(idc.GetFunctionName(f),)
        fAddr=GetFunctionAttr(f,FUNCATTR_START)
        f = idaapi.FlowChart(idaapi.get_func(f),flags=idaapi.FC_PREDS)
        calculate_weight(f,fAddr)
        

def main():
    # TODO: ask for the pickled file that contains so far discovered BB's weights.
    ## TODO: it is perhaps a better idea to check "idaapi.get_imagebase()" so that at runtime, we can calculate correct address from this static compile time address.
    strings=[]
    start = timeit.default_timer()
    analysis()
    strings=findCMPopnds()
    stop = timeit.default_timer()
    
    for bb in weight:
        fweight[bb]=(1.0/weight[bb][0],weight[bb][1])
    print"[**] Printing weights..."
    for bb in fweight:
        print "BB [%x-%x] -> %3.2f"%(bb,fweight[bb][1],fweight[bb][0])
    print " [**] Total Time: ", stop - start
    print "[**] Total functions analyzed: %d"%(fCount,)
    print "[**] Total BB analyzed: %d"%(len(fweight),)
    outFile=GetInputFile() # name of the that is being analysed
    strFile=outFile+".names"
    outFile=outFile+".pkl"
    fd=open(outFile,'w')
    pickle.dump(fweight,fd)
    fd.close()
    strFD=open(strFile,'w')
    pickle.dump(strings,strFD)
    strFD.close()
    print "[*] Saved results in pickle files: %s, %s"%(outFile,strFile)

if __name__ == "__main__":
    main()
