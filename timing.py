import atexit
#from time import clock
from time import time

def secondsToStr(t):
    return "%d:%02d:%02d.%03d" % \
        reduce(lambda ll,b : divmod(ll[0],b) + ll[1:],
            [(t*1000,),1000,60,60])

line = "="*40
def log(s, elapsed=None):
    print line
    #print secondsToStr(clock()), '-', s
    print secondsToStr(time()), '-', s
    if elapsed:
        print "Elapsed time:", elapsed
    print line
    print

def endlog():
    #end = clock()
    end = time()
    elapsed = end-start
    log("End Program", secondsToStr(elapsed))

def now():
    #return secondsToStr(clock())
    return secondsToStr(time())

#start = clock()
start = time()
atexit.register(endlog)
log("Start Program")
