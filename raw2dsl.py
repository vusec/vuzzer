#!/usr/bin/env python

# Converter from our custom raw provenance output to SPADE DSL format.
# See: https://code.google.com/p/data-provenance/wiki/Pipe

from raw2ttl import RawConverter
from raw2ttl import Error, UnknownUFDError
import argparse
import fileinput
from operator import itemgetter
from textwrap import dedent
from time import gmtime, strftime

# from pprint import pprint

# type:<Agent|Process|Artifact> id:<unique identifier> <key>:<value> ... <key>:<value>
# type:<Used|WasGeneratedBy|WasTriggeredBy|WasDerivedFrom|WasControlledBy> from:<unique identifier> to:<unique identifier> <key>:<value> ... <key>:<value> 

##########################################################################################
# XXX: after a fork() provenance of two processes may be interleaved in the raw output.
#      for this, pid probably has to be printed with every line in the raw output.
#	   also, locking may be required when dumping to the raw output. 
##########################################################################################

#### Exceptions #####################################################
class NoVertexIDError(Error):
	"""Raised when there's no vid for an artifact."""
	def __init__(self, artifact):
		self.artifact = artifact
	def __str__(self):
		return "No vertex id found for artifact %s." % (self.artifact)



#### SPADE DSL converter class ###################################
class RawDSLConverter(RawConverter):
	formats = {
		'program_vertex': dedent('''
			type:Process id:{proc_vid} program:{program} pid:{pid}
		''').strip(),
		'file_vertex': dedent('''
			type:Artifact id:{file_vid} filename:{filename} label:"{label}"
		''').strip(),
		'range_vertex': dedent('''
			type:Artifact id:{range_vid} file:{rangename} memberof:{file_vid}
		''').strip(),

		'used': dedent('''
			type:Used from:{proc_vid} to:{file_vid}
		''').strip(),
		'derived': dedent('''
			type:WasDerivedFrom from:{file_vid1} to:{file_vid2}
		''').strip(),
		'generated': dedent('''
			type:WasGeneratedBy from:{file_vid} to:{proc_vid}
		''').strip(),

		'range': '{filename}[{start},{end}]',

		# not used for now
		'derived_range': dedent('''
			<{filename1}{range1}> prov:wasDerivedFrom <{filename2}{range2}> .
		''').strip(),

	}

	def __init__(self, keepcomments=True, keepbad=False, minrange=0):
		super(RawDSLConverter, self).__init__(keepcomments, keepbad, minrange)

		# Compute the base for the unique vertex ids created by this session.
		# This will produce something like this: 201504141812190000.
		# The base can then be incremented to get (hopefully) unique ids.
		self.vid_base = int(strftime("%Y%m%d%H%M%S", gmtime())) * (10**4)
		self.vid_next = self.vid_base
		self.vid_files = {}
		self.vid_procs = {}

	def get_file_vid(self, filename, makenew=True):
		""" Returns the vertex id for the specified file.
		"""
		if filename not in self.vid_files:
			if not makenew:
				raise NoVertexIDError(filename)
			else:
				self.vid_files[filename] = self.vid_next
				self.vid_next+=1
		return self.vid_files[filename]

	def get_proc_vid(self, program=None, pid=None, makenew=True):
		""" Returns the vertex id for the specified process.
		"""
		makenew = False if (program is None or pid is None) else makenew
		program = self.exe if (program is None) else program
		pid = self.pid if (pid is None) else pid

		k = '%s[%s]' % (program, pid)
		if k not in self.vid_procs:
			if not makenew:
				raise NoVertexIDError(k)
			else:
				self.vid_procs[k] = self.vid_next
				self.vid_next+=1
		return self.vid_procs[k]

	def handle_c(self, data):
		ufd = itemgetter('ufd')(data)
		filename1 = self.ufdmap[ufd]

		# print triples
		if ufd in self.derived:
			for filename2 in self.derived[ufd]:
				print self.format('derived',
					file_vid1 = self.get_file_vid(filename1, False),
					file_vid2 = self.get_file_vid(filename2, False),
				)
			del self.derived[ufd]

		# cleanup generated
		if filename1 in self.generated: self.generated.remove(filename1)

	def handle_g(self, data):
		mode, exe, filename = itemgetter('mode', 'program', 'file')(data)
		assert self.exe == exe, "Unexpected change to executable name. Expected %s. Got %s." % (self.exe, exe)

		if mode == 't' or mode == 'g':
			print self.format('generated',
				proc_vid = self.get_proc_vid(),
				file_vid = self.get_file_vid(filename, False),
			)
		else:
			#do not generate triple yet - it will be generated on first write
			self.generated.add(filename);

	def handle_o(self, data):
		ufd, filename = itemgetter('ufd', 'file')(data)
		self.ufdmap[ufd] = filename

		print self.format('file_vertex',
			file_vid = self.get_file_vid(filename),
			filename = self.__class__.quote_file(filename),
			label = filename
		)

	def handle_u(self, data):
		exe, filename = itemgetter('program', 'file')(data)
		assert self.exe == exe, "Unexpected change to executable name. Expected %s. Got %s." % (self.exe, exe)
		print self.format('used',
			proc_vid = self.get_proc_vid(),
			file_vid = self.get_file_vid(filename, False),
		)

	def handle_w(self, data):
		rtype, ufd, offset, origin_ufd, origin_offset, length = itemgetter(
			'range_type', 'out_ufd', 'out_offset', 'origin_ufd', 'origin_offset', 'length'
		)(data)

		if ufd not in self.ufdmap:
			raise UnknownUFDError(ufd)
		if origin_ufd not in self.ufdmap:
			raise UnknownUFDError(origin_ufd)

		filename = self.ufdmap[ufd]
		filename_origin = self.ufdmap[origin_ufd]
		offset = int(offset)
		origin_offset = int(origin_offset)
		length = int(length)

		# emit generated triple if needed
		if filename in self.generated:
			print self.format('generated',
				proc_vid = self.get_proc_vid(),
				file_vid = self.get_file_vid(filename, False),
			)
			self.generated.remove(filename)

		# simple file provenance
		if ufd in self.derived:
			self.derived[ufd].add(filename_origin)
		else:
			self.derived[ufd] = set([filename_origin])

		# output ranges
		if self.minrange > 0 and length >= self.minrange:
			if rtype == 'SEQ':
				range_origin = self.format('range',
					filename = self.__class__.quote_file(filename_origin),
					start = origin_offset,
					end = origin_offset+length-1
				)
				range_dest = self.format('range',
					filename = self.__class__.quote_file(filename),
					start = offset,
					end = offset+length-1
				)
			elif rtype == 'REP':
				range_origin = self.format('range',
					filename = self.__class__.quote_file(filename_origin),
					start = origin_offset,
					end = origin_offset
				)
				range_dest = self.format('range',
					filename = self.__class__.quote_file(filename),
					start = offset,
					end = offset+length-1
				)
			else:
				# temp fix for NONE ranges
				# the script will run, but they will be missed	
				return

			print self.format('range_vertex',
				range_vid = self.get_file_vid(range_origin),
				rangename = range_origin,
				file_vid = self.get_file_vid(filename_origin, False)
			)
			print self.format('range_vertex',
				range_vid = self.get_file_vid(range_dest),
				rangename = range_dest,
				file_vid = self.get_file_vid(filename, False)
			)
			print self.format('derived',
				file_vid1 = self.get_file_vid(range_origin, False),
				file_vid2 = self.get_file_vid(range_dest, False),
			)


	def handle_x(self, data):
		self.pid, self.exe = itemgetter('pid', 'program')(data)
		self.generated.clear()

		print self.format('program_vertex',
			proc_vid = self.get_proc_vid(self.exe, self.pid),
			pid = self.pid,
			program = self.__class__.quote_file(self.exe),
		)


#### main ###########################################################
if __name__ == "__main__":
	tag_range = {}

	parser = argparse.ArgumentParser(description='Convert DataTracker raw format to input for the SPADE DSL Reporter.')
	parser.add_argument('-minrange', type=int, default=0, help='the minimum range size to be included in the output')
	# parser.add_argument('dsl-pipe', metavar='pipe', nargs='*', help='location of the SPADE DSL pipe')
	parser.add_argument('files', metavar='file', nargs='*', help='specify input files')
	args = parser.parse_args()

	converter = RawDSLConverter(keepcomments=False, keepbad=False, minrange=getattr(args, 'minrange', 0))

	for line in fileinput.input(args.files):
		converter.process_line(line)
