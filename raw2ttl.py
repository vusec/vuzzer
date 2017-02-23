#!/usr/bin/env python

# Converter from our custom raw provenance output to turtle output.
# See: http://www.w3.org/TeamSubmission/turtle/  
#
# The RawConverter class contained here also serves as a base for 
# building converters for other formats.

from abc import ABCMeta

import argparse
import sys
import fileinput
import string
import urllib
import inspect
from operator import itemgetter
from textwrap import dedent
from pprint import pprint



#### Exceptions #####################################################
class Error(Exception):
	"""Base class for exceptions in this module."""
	pass

class UnknownUFDError(Error):
	"""Raised when there's no mapping for an ufd."""
	def __init__(self, ufd):
		self.ufd = ufd
	def __str__(self):
		return "No active mapping for %s." % (self.ufd)

class TagFormatError(Error):
	"""Raised when tags cannot be parsed."""
	def __init__(self, tagspec):
		self.tagspec = tagspec
	def __str__(self):
		return "Cannot parse '%s' into tags." % (self.tagspec)

class RangeError(Error):
	pass



#### Classes for used data types ####################################
class Range:
	start = 0
	end = 0

	def __init__(self, start, end=None):
		self.start = start
		self.end = self.start if end == None else end
		if self.end < self.start:
			self.start = self.end
			self.end = start

	def expand(self, n=1):
		self.end += n

	def lexpand(self, n=1):
		self.start -= n

	def length(self):
		return self.start-self.end

	def join(self, range2):
		if not self.is_adjacent(range2):
			raise RangeError("Attempting to join not adjacent ranges.")

	def is_adjacent(self, range2):
		if isinstance(range2, self.__class__):
			if range2.end == self.start-1 or range2.start == self.end+1:
				return True
			return False
		elif isinstance(range2, int):
			if range2 == self.start-1 or range2 == self.end+1:
				return True
			return False
		else:
			raise RangeError("Unsupported argument type.")

	def is_overlapping(self, range2):
		if range2.start <= self.start and range2.end <= self.start:
			return False
		if range2.start >= self.end and range2.end >= self.end:
			return False
		return True

	def __str__(self):
		return "%d-%d" % (self.start, self.end)




#### Base converter class ###########################################
class RawConverter:
	""" Base class for raw provenance converters.

	The class encapsulates the processing of the input lines.
	Lines are parsed into a dict by process_line() and then passed
	to the appropriate handler which should be implemented by the
	subclass.
	The expected format of each line is defined in the input_formats
	dict.
	"""
	__metaclass__ = ABCMeta
	formats = {}
	input_formats = {
		'c': (['ufd'], 0),
		'g': (['mode', 'program', 'file'], 2),
		'o': (['ufd', 'file'], 1),
		'u': (['program', 'file'], 1),
		'w': (['range_type', 'out_ufd', 'out_offset', 'origin_ufd', 'origin_offset', 'length'], 5),
		'x': (['pid', 'program'], 1),
	}
	exe = None
	pid = -1
	ufdmap = {}
	derived = {}
	generated = set()

	def __init__(self, keepcomments=True, keepbad=False, minrange=0):
		self.keepcomments = keepcomments
		self.keepbad = keepbad
		self.minrange = minrange
		self.output_static('header')
		self.handlers = dict(filter(
			lambda t: t[0].startswith('handle_'),
			inspect.getmembers(self, predicate=inspect.ismethod)
		))

	def format(self, fmt, **kwargs):
		return self.formats[fmt].format(**kwargs)

	def output_static(self, what):
		if what in self.formats:
			print self.formats[what]

	def output_format(self, fmt, **kwargs):
		print self.formats(fmt).format(**kwargs)

	def process_line(self, line):
		line = line.strip()

		if line.startswith('#'):
			if self.keepcomments:
				print line
		else:
			op, data =  line.strip().split(':', 1)

			try:
				# Combine line format and data into a dict.
				keys, nsplits = self.input_formats[op]	
				data_dict = dict(zip(keys, data.split(':', nsplits)))

				# Call the handler with the data in the dict.
				self.handlers['handle_'+op](data_dict)
			except KeyError:
				# Keep bad lines as comments
				if self.keepbad:
					print '#BAD '+line
				else:
					raise

	@classmethod
	def quote_file(cls, filename, asURL=False):
		if asURL:
			return 'file://'+urllib.pathname2url(filename)
		else:
			return '"%s"' % (filename)



#### Turtle converter class ######################################
class RawTTLConverter(RawConverter):
	formats = {
		'header': dedent('''
			@prefix prov: <http://www.w3.org/ns/prov#> .
			@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .
		''').strip(),
		'derived': dedent('''
			<{filename1}> prov:wasDerivedFrom <{filename2}> .
		''').strip(),
		'derived_range': dedent('''
			<{filename1}{range1}> prov:wasDerivedFrom <{filename2}{range2}> .
		''').strip(),
		'exec': dedent('''
			<{url_program}> a prov:Activity .
		''').strip(),
		'generated': dedent('''
			<{filename}> prov:wasGeneratedBy <{url_program}> .
		''').strip(),
		'member': dedent('''
			<{filename}> prov:hadMember <{filename}{range}> .
		''').strip(),
		'open': dedent('''
			<{filename}> a prov:Entity .
			<{filename}> rdfs:label "{label}" .
		''').strip(),
		'used': dedent('''
			<{url_program}> prov:used <{filename}> .
		''').strip(),
		'file_range': '#%d-%d',
	}

	@classmethod
	def quote_file(cls, filename, asURL=True):
		return super(RawTTLConverter, cls).quote_file(filename, asURL)

	def handle_c(self, data):
		ufd = itemgetter('ufd')(data)
		filename1 = self.ufdmap[ufd]

		if ufd in self.derived:
			for filename2 in self.derived[ufd]:
				print self.format('derived',
					filename1 = self.__class__.quote_file(filename1),
					filename2 = self.__class__.quote_file(filename2),
				)
			del self.derived[ufd]

		# cleanup generated
		if filename1 in self.generated: self.generated.remove(filename1)

	def handle_g(self, data):
		mode, exe, filename = itemgetter('mode', 'program', 'file')(data)
		assert self.exe == exe, "Unexpected change to executable name. Expected %s. Got %s." % (self.exe, exe)

		if mode == 't' or mode == 'g':
			print self.format('generated',
				url_program = self.__class__.quote_file(self.exe),
				filename = self.__class__.quote_file(filename),
			)
		else:
			#do not generate triple yet - it will be generated on first write
			self.generated.add(filename);

	def handle_o(self, data):
		ufd, filename = itemgetter('ufd', 'file')(data)
		self.ufdmap[ufd] = filename

		print self.format('open',
			filename = self.__class__.quote_file(filename),
			label = filename
		)

	def handle_u(self, data):
		exe, filename = itemgetter('program', 'file')(data)
		assert self.exe == exe, "Unexpected change to executable name. Expected %s. Got %s." % (self.exe, exe)

		print self.format('used',
			url_program = self.__class__.quote_file(exe),
			filename = self.__class__.quote_file(filename),
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
				url_program = self.__class__.quote_file(self.exe),
				filename = self.__class__.quote_file(filename),
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
				print self.format('member',
					filename = self.__class__.quote_file(filename),
					range = file_range_fmt % (offset, offset+length-1)
				)
				print self.format('member',
					filename = self.__class__.quote_file(filename_origin),
					range = file_range_fmt % (origin_offset, origin_offset+length-1)
				)
				print self.format('derived_range',
					filename1 = self.__class__.quote_file(filename),
					range1 = file_range_fmt % (offset, offset+length-1),
					filename2 = self.__class__.quote_file(filename_origin),
					range2 = file_range_fmt % (origin_offset, origin_offset+length-1)
				)
			elif rtype == 'REP':
				print self.format('member',
					filename = self.__class__.quote_file(filename),
					range = file_range_fmt % (offset, offset+length-1)
				)
				print self.format('member',
					filename = self.__class__.quote_file(filename_origin),
					range = file_range_fmt % (origin_offset, origin_offset)
				)
				print self.format('derived_range',
					filename1 = self.__class__.quote_file(filename),
					range1 = file_range_fmt % (offset, offset+length-1),
					filename2 = self.__class__.quote_file(filename_origin),
					range2 = file_range_fmt % (origin_offset, origin_offset)
				)

		# TODO: Aggregation per written buffer is done inside dtracker.
		# Additional aggregation may be done here.

	def handle_x(self, data):
		pid, self.exe = itemgetter('pid', 'program')(data)
		self.generated.clear()

		print self.format('exec',
			url_program = self.__class__.quote_file(self.exe),
		)


#### main ###########################################################
if __name__ == "__main__":
	tag_range = {}

	parser = argparse.ArgumentParser(description='Convert DataTracker raw format to PROV/Turtle format.')
	parser.add_argument('-minrange', type=int, default=0, help='the minimum range size to be included in the output')
	parser.add_argument('files', metavar='file', nargs='*', help='specify input files')
	args = parser.parse_args()

	converter = RawTTLConverter(minrange=args.minrange)

	for line in fileinput.input(args.files):
		converter.process_line(line)
