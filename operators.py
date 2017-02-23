"""
operators.py
    This files implements GA operators viz mutation and crossover for fuzzing data.

This is partly based on mutation implementation by Jesse Burns (jesse@isecpartners.com)
"""
import random
import config

class GAoperator:
    """ create it with a random and have it manipulate data for you. """
    DENOM = 50 # change at most 0-2 % of the binary with each fuzz
    r = None
    int_slide_position = 0
    slide_step = 1
    #ALL_CHARS = ''.join([chr(n) for n in xrange(256)])
    ALL_CHARS = [chr(n) for n in xrange(256)]
    HIGH_CHARS= [chr(n) for n in xrange(128,256)]
  
    def __init__(self, random_object, extra, demoninator = 50):
        ''' the 3rd parameter extra us a list of two sets. 1st set is a set of full strings from binary, whereas 2nd set is a set of individual bytes from those strings.
''' 
        self.DENOM = demoninator
        self.r = random_object
        self.full=list(extra[0])
        self.obytes=list(extra[1])
        if len(self.full)>0:
            self.allStrings=[self.full,self.full,self.HIGH_CHARS,self.obytes]
            #self.allStrings=[self.full,self.full,self.full,self.obytes]
        elif len(self.obytes)>0:
            #self.allStrings=[self.ALL_CHARS,self.obytes,self.obytes,self.obytes]
            self.allStrings=[self.obytes,self.obytes,self.HIGH_CHARS]
        else:
            self.allStrings=[self.ALL_CHARS]
    #print len(self.allStrings)
    #print self.bytes
    #print self.full
    #print self.ALL_CHARS

  #def random_string(self, size, char_set = ALL_CHARS):
    #return ''.join([self.r.choice(char_set) for n in xrange(size)] 
    def get_cut(self,size,fl):
        print "in get_cut\n"
        if len(config.TAINTMAP)>0 and random.randint(0,9)>3:
            onlyCom=False
            
            if fl in config.TAINTMAP:
                tof=config.TAINTMAP[fl][0]
            else:
                tfl=self.r.choice(config.TAINTMAP.keys())
                tof=config.TAINTMAP[tfl][0]
        else:
            onlyCom=True
            

        #right=False
        #while right!=True:
            #cut_pos = self.r.randint(0, size)
        if onlyCom==False:
            tset=set(tof)-set(config.MOSTCOMMON)
            if len(tset)>0:
                ltset=filter(lambda x:x<size, tset)
                if len(ltset)>0:
                    cut_pos=self.r.choice(ltset)
                    print "offset %d"%(cut_pos,)
                else:
                    cut_pos=self.r.randint(0,size)
                    print "random offset %d"%(cut_pos,)
            else:
                right=False
                while right ==False:
                    cut_pos = self.r.randint(0, size)
                    if cut_pos not in config.MOSTCOMMON:
                        right = True
                        print "random offset %d"%(cut_pos,)

                #if cut_pos not in config.MOSTCOMMON and cut_pos in tof:
                #    right = True
        else:
            right=False
            while right ==False:
                cut_pos = self.r.randint(0, size)
                if cut_pos not in config.MOSTCOMMON:
                    right = True
                    print "random offset %d"%(cut_pos,)
        return cut_pos
   

    def random_string(self, size, source=None):
        if source is None:
            source=self.allStrings
        result=''
        while len(result)<size:
            result=result+self.r.choice(self.r.choice(source))
        #return ''.join([self.r.choice(self.r.choice(self.allStrings)) for n in xrange(size)])
        return result

    def eliminate_random(self, original,fl):
        size = len(original)
        cut_size = max(1, self.r.randint(1, max(1, size/self.DENOM)))
        #cut_pos = self.r.randint(0, size - cut_size)
        cut_pos = self.get_cut(size - cut_size,fl)
        result = original[:cut_pos] + original[cut_pos + cut_size:]
        #assert len(original) > len(result), "elimination failed to reduce size %d %d" % (len(original), len(result))
        return result

    def eliminate_random_end(self, original,fl):
        size = len(original)
        cut_size = max(1, self.r.randint(1, max(1, size/self.DENOM)))
        cut_pos = self.r.randint(size/2, size - cut_size)
        result = original[:cut_pos] + original[cut_pos + cut_size:]
        #assert len(original) > len(result), "elimination failed to reduce size %d %d" % (len(original), len(result))
        return result

    def double_eliminate(self, original,fl):
        result=self.eliminate_random_end(original,fl)
        return self.eliminate_random(result,fl)

    def add_random(self, original,fl):
        size = len(original)
        add_size = max(1, self.r.randint(1, max(1, size/self.DENOM)))
        cut_pos=self.get_cut(size-add_size,fl)
        #right=False
        #while right!=True:
        #    cut_pos = self.r.randint(0, size - add_size)
        #     if cut_pos not in config.MOSTCOMMON:
        #         right = True

        result = ''.join([original[:cut_pos], self.random_string(add_size), original[cut_pos:]])
        #assert len(original) < len(result), "adding failed to increase size  %d %d" % (len(original), len(result))
        return self.change_bytes(result,fl)
  
    def change_random(self, original,fl):
        size = len(original)
        add_size = max(1, self.r.randint(1, max(1, size/self.DENOM)))
        cut_pos = self.get_cut(size - add_size,fl)
        result = ''.join([original[:cut_pos], self.random_string(add_size), original[cut_pos + add_size:]])
        #assert len(original) == len(result), "size changed on a random change %d %d" % (len(original), len(result))
        return self.change_bytes(result,fl)

    def change_bytes(self,original,fl):
        if len(config.TAINTMAP)==0:
            return original
        lorig=list(original)
        if fl in config.TAINTMAP:
            tof=config.TAINTMAP[fl][0]
        else:
            tfl=random.choice(config.TAINTMAP.keys())
            tof=config.TAINTMAP[tfl][0]
        tset=tof-set(config.MOSTCOMMON)
        #print "in change bytes..",tof, tset
        #raw_input("press enter...")
        if len(tset)>0:

            cset=self.r.sample(tset,max(1,len(tset)/4))
            for of in cset:
                if of>len(lorig)-1 or of < -len(lorig):
                    continue
                lorig[of]=self.r.choice(self.ALL_CHARS)
            result=''.join([e for e in lorig])
            return result
        print "[*] 0 offset set"
        return original

    def change_random_full(self, original,fl):
        size = len(original)
        add_size = max(1, self.r.randint(1, max(1, size/self.DENOM)))
        cut_pos = self.r.randint(0, size - add_size)
        if len(self.full)>1:
            #result = ''.join([original[:cut_pos], self.r.choice(self.full), original[cut_pos:]])
            result = ''.join([original[:cut_pos], self.random_string(add_size,[self.full]), original[cut_pos:]])
    #assert len(original) == len(result), "size changed on a random change %d %d" % (len(original), len(result))
            return result
        elif len(self.obytes)>2 and size >3:
            pos=self.r.sample([k for k in xrange(1,size-1)],2)
            result = ''.join([original[:pos[0]], self.r.choice(self.obytes),original[pos[0]:pos[1]],self.r.choice(self.obytes), original[pos[1]:]])
        #assert len(original) == len(result), "size changed on a random change %d %d" % (len(original), len(result))
            return result
        else:
            result = ''.join([original[:cut_pos], self.random_string(add_size), original[cut_pos + add_size:]])
    #assert len(original) == len(result), "size changed on a random change %d %d" % (len(original), len(result))
        return result
  
    def single_change_random(self, original,fl):
        changes = self.r.randint(1, 100)
        size = len(original)
        for a in xrange(changes):
            cut_pos = self.r.randint(1, size)
            original = ''.join([original[:cut_pos - 1], chr(self.r.randint(1, 255)), original[cut_pos:]])
            #original = ''.join([original[:cut_pos - 1], self.r.choice(self.bytes), original[cut_pos:]])
        #assert len(original) == size, "size changed on a random tweak %d %d" % (len(original), size)
        return original
  
    def lower_single_random(self, original,fl):
        changes = self.r.randint(1, 100)
        size = len(original)
        result = original
        for a in xrange(changes):
            cut_pos = self.r.randint(1, size)
            result = ''.join([result[:cut_pos - 1], chr(max(0, ord(result[cut_pos - 1]) - 1)), result[cut_pos:]])
        #assert len(result) == size, "size changed on a random tweak %d %d" % (len(original), size)
        # assert result != original, "nothing changed in lower_single_random %d - actually this can happen due to max above" % changes
        return result
      
    def raise_single_random(self, original,fl):
        changes = self.r.randint(1, 100)
        size = len(original)
        result = original
        for a in xrange(changes):
            cut_pos = self.r.randint(1, size)
            result = result[:cut_pos - 1] + chr(min(255, ord(result[cut_pos - 1]) + 1)) + result[cut_pos:]
        #assert len(result) == size, "size changed on a random tweak %d %d" % (len(original), size)
        #assert result != original, "nothing changed in lower_single_random %d - actually this can happen due to min above" % changes
        return result
  
    def eliminate_null(self, original, fl,replacement = 'A'):
        size = len(original)
        cut_pos = original.find('\0', self.r.randint(0, size))
        if (cut_pos != -1):
            result = ''.join([original[:cut_pos], replacement, original[cut_pos + 1:]])
        else:
            return original
        #assert len(original) == len(result), "size changed on a null elmination change %d %d" % (len(original), len(result))
        return result
  
    def eliminate_double_null(self, original, fl,replacement = 'AA'):
        size = len(original) - 1
        cut_pos = original.find('\0\0', self.r.randint(0, size))
        if (cut_pos != -1):
            result = ''.join([original[:cut_pos], replacement, original[cut_pos + 2:]])
        else:
            return original
        #assert len(original) == len(result), "size changed on a null elmination change %d %d" % (len(original), len(result))
        return result
  
    def totally_random(self, original,fl):
        size = len(original)
        return self.random_string(self.r.randint(100, 1000))
       # return ''.join([self.r.choice(self.r.choice(self.allStrings+self.full)) for n in xrange(size)])

    def int_slide(self, original,fl):
        size = len(original)
        value = self.r.choice(['\xFF\xFF\xFF\xFF', '\x80\x00\x00\x00', '\x00\x00\x00\x00'])#, '\xAA\xAA\xAA\xAA', '\x41\x41\x41\x41'])
        if size < 4 : return value[:size]
        start = self.int_slide_position % size
        if start > size - 4: 
            result = original[:start] + value
        else:
            result = ''.join([original[:start], value, original[start + 4:]])
        self.int_slide_position += self.slide_step
        return result

    def double_fuzz(self, original,fl):
        """ runs two fuzzers (one or more of which could be double_fuzz itself! """
        result = self.r.choice(self.mutators)(self, original,fl)
        return self.r.choice(self.mutators)(self, result,fl)

    def double_full_mutate(self,original,fl):
        ''' This is called to do heavy mutation when no progress is made in previous generations. '''
        result = self.change_random_full(original,fl)
        return self.change_random_full(result,fl)
  
    def single_crossover(self, original1, original2):
        """ This function computes single-point crossover on two parents and returns two children.
"""
        point=self.r.uniform(0.1,0.6)
        cut1=int(point*len(original1))
        cut2=int(point*len(original2))
        child1=original1[:cut1]+original2[cut2:]
        child2=original2[:cut2]+original1[cut1:]
        return child1, child2
  
    def double_crossover(self, original1, original2):
        """This function computes 2-point crossover on two parents and returns two children.
"""
        point1=self.r.uniform(0.1,0.3)
        point2=self.r.uniform(0.6,0.8)
        len1=len(original1)
        len2=len(original2)
        cut11=int(point1*len1)
        cut12=int(point2*len1)
        cut21=int(point1*len2)
        cut22=int(point2*len2)
        child1=original1[:cut11]+original2[cut21:cut22]+original1[cut12:]
        child2=original2[:cut21]+original1[cut11:cut12]+original2[cut22:]
        return child1, child2
    
    crossovers=[single_crossover, double_crossover]

    ##NOTE: we added few mutators more than one so that such operations can be frequent. added ones are: eliminate_random, change_random_full
    mutators = [eliminate_random, change_bytes, change_bytes,add_random, add_random, change_random,single_change_random, lower_single_random, raise_single_random, eliminate_null, eliminate_double_null, totally_random, int_slide, double_fuzz,change_random_full,change_random_full,eliminate_random,add_random, change_random]
  
    def mutate(self, original,fl):
        result=self.r.choice(self.mutators)(self, original,fl)
        while len(result)<3:
            result= self.r.choice(self.mutators)(self, original,fl)
        assert len(result)>2, "elimination failed to reduce size %d" % (len(result),)
        return result

    def eliminate(self, original,fl):
        loop=self.r.randint(0,3)
        result = self.r.choice([self.double_eliminate,self.eliminate_random])(original,fl)
        if 4<len(result)<10:
            return result
        else:
            return original
        for i in range(loop):
            temp=result
            result = self.r.choice([self.double_eliminate,self.eliminate_random])(result,fl)
        if len(result)<10:
            return temp
        return result


    def crossover(self, original1, original2):
        minlen=min(len(original1), len(original2))
        if minlen <20:
            return original1, original2 # we don't do any crossover as parents are two young to have babies ;)
        return self.r.choice(self.crossovers)(self, original1,original2)
