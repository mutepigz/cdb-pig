from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
import tempfile
import pprint
import inspect
import os
import sys
import struct
import string
import re
import itertools
import functools
from subprocess import *

import codecs

import six
from six import StringIO
from six.moves import range
from six.moves import input
from color import cprint,debug
from time import time

class memoized(object):
	"""
	Decorator. Caches a function's return value each time it is called.
	If called later with the same arguments, the cached value is returned
	(not reevaluated).
	"""
	def __init__(self, func):
		self.func = func
		self.instance = None # bind with instance class of decorated method
		self.cache = {}
		self.__doc__ = inspect.getdoc(self.func)

	def __call__(self, *args, **kwargs):
		try:
			return self.cache[(self.func, self.instance, args) + tuple(kwargs.items())]
		except KeyError:
			if self.instance is None:
				value = self.func(*args, **kwargs)
			else:
				value = self.func(self.instance, *args, **kwargs)
			self.cache[(self.func, self.instance, args) + tuple(kwargs.items())] = value
			return value
		except TypeError:
			# uncachable -- for instance, passing a list as an argument.
			# Better to not cache than to blow up entirely.
			if self.instance is None:
				return self.func(*args, **kwargs)
			else:
				return self.func(self.instance, *args, **kwargs)

	def __repr__(self):
		"""Return the function's docstring."""
		return self.__doc__

	def __get__(self, obj, objtype):
		"""Support instance methods."""
		if obj is None:
			return self
		else:
			self.instance = obj
			return self

	def _reset(self):
		"""Reset the cache"""
		# Make list to prevent modifying dictionary while iterating
		for cached in list(self.cache.keys()):
			if cached[0] == self.func and cached[1] == self.instance:
				del self.cache[cached]

def reset_cache(module=None):
	"""
	Reset memoized caches of an instance/module
	"""
	if module is None:
		module = sys.modules['__main__']

	for m in dir(module):
		m = getattr(module, m)
		if isinstance(m, memoized):
			m._reset()
		else:
			for f in dir(m):
				f = getattr(m, f)
				if isinstance(f, memoized):
					f._reset()

	return True

def colorize(text, color=None, attrib=None):
	"""
	Colorize text using ansicolor
	ref: https://github.com/hellman/libcolors/blob/master/libcolors.py
	"""
	# ansicolor definitions
	COLORS = {"black": "30", "red": "31", "green": "32", "yellow": "33",
				"cyan": "34", "purple": "35", "blue": "36", "white": "37",
				"brown": "86","lightcyan": "87","lightmagenta": "88","magenta": "89",
				"darkgray": "90",}
	CATTRS = {"regular": "0", "bold": "1", "underline": "4", "strike": "9",
				"light": "1", "dark": "2", "invert": "7"}

	CPRE = '\033['
	CSUF = '\033[0m'

	if not color:
		color = "white"

	ccode = ""
	if attrib:
		for attr in attrib.lower().split():
			attr = attr.strip(",+|")
			if attr in CATTRS:
				ccode += ";" + CATTRS[attr]
	if color in COLORS:
		ccode += ";" + COLORS[color]
	return CPRE + ccode + "m" + text + CSUF

def green(text, attrib=None):
	"""Wrapper for colorize(text, 'green')"""
	return colorize(text, "green", attrib)

def red(text, attrib=None):
	"""Wrapper for colorize(text, 'red')"""
	return colorize(text, "red", attrib)

def yellow(text, attrib=None):
	"""Wrapper for colorize(text, 'yellow')"""
	return colorize(text, "yellow", attrib)

def cyan(text, attrib=None):
	"""Wrapper for colorize(text, 'blue')"""
	return colorize(text, "blue", attrib)

def purple(text, attrib=None):
	"""Wrapper for colorize(text, 'blue')"""
	return colorize(text, "purple", attrib)

def blue(text, attrib=None):
	"""Wrapper for colorize(text, 'blue')"""
	return colorize(text, "cyan", attrib)

def brown(text, attrib=None):
	"""Wrapper for colorize(text, 'blue')"""
	return colorize(text, "brown", attrib)

def lightcyan(text, attrib=None):
	"""Wrapper for colorize(text, 'blue')"""
	return colorize(text, "lightcyan", attrib)

def lightmagenta(text, attrib=None):
	"""Wrapper for colorize(text, 'blue')"""
	return colorize(text, "lightmagenta", attrib)

def magenta(text, attrib=None):
	"""Wrapper for colorize(text, 'blue')"""
	return colorize(text, "magenta", attrib)


def clearscreen():
	"""Clear terminal screen"""
	sys.stdout.write("\x1b[2J\x1b[H")

def trim(docstring):
	"""
	Handle docstring indentation, ref: PEP257
	"""
	if not docstring:
		return ''
	# Convert tabs to spaces (following the normal Python rules)
	# and split into a list of lines:
	lines = docstring.expandtabs().splitlines()
	# Determine minimum indentation (first line doesn't count):
	max_indent = sys.maxsize
	indent = max_indent
	for line in lines[1:]:
		stripped = line.lstrip()
		if stripped:
			indent = min(indent, len(line) - len(stripped))
	# Remove indentation (first line is special):
	trimmed = [lines[0].strip()]
	if indent < max_indent:
		for line in lines[1:]:
			trimmed.append(line[indent:].rstrip())
	# Strip off trailing and leading blank lines:
	while trimmed and not trimmed[-1]:
		trimmed.pop()
	while trimmed and not trimmed[0]:
		trimmed.pop(0)
	# Return a single string:
	return '\n'.join(trimmed)

def is_printable(text, printables=""):
	"""
	Check if a string is printable
	"""
	if six.PY3 and isinstance(text, six.string_types):
		text = six.b(text)
	if len(text)<=0:
		return False
	return set(text) - set(six.b(string.printable) + six.b(printables)) == set()

def is_math_exp(str):
	"""
	Check if a string is a math exprssion
	"""
	charset = set("0123456789abcdefx+-*/%^")
	opers = set("+-*/%^")
	exp = set(str.lower())
	return (exp & opers != set()) and (exp - charset == set())

def normalize_argv(args, size=0):
	"""
	Normalize argv to list with predefined length
	"""
	args = list(args)
	for (idx, val) in enumerate(args):
		if to_int(val) is not None:
			args[idx] = to_int(val)
		if size and idx == size:
			return args[:idx]

	if size == 0:
		return args
	for i in range(len(args), size):
		args += [None]
	return args

def to_hexstr(str_):
	"""
	Convert a binary string to hex escape format
	"""
	return "".join(["\\x%02x" % ord(i) for i in bytes_iterator(str_)])

def to_hex(num):
	"""
	Convert a number to hex format
	"""
	if num < 0:
		return "-0x%x" % (-num)
	else:
		return "0x%x" % num

def just_hex(num, j=0):
	"""
	Convert a number to adjust hex format.
	"""
	if num < 0:
		return ("%x" % (-num)).rjust(j,'0')
	else:
		return ("%x" % num).rjust(j,'0')

def to_address(num):
	"""
	Convert a number to address format in hex
	"""
	if num < 0:
		return to_hex(num)
	if num > 0xffffffff: # 64 bit
		return "0x%016x" % num
	else:
		return "0x%08x" % num

def to_int(val):
	"""
	Convert a string to int number
	"""
	if (val.startswith("0x")):
		val = val[2:]
	try:
		val = val.replace("`","")
		return int(str(val), 16)
	except:
		return 0

def str2hex(str):
	"""
	Convert a string to hex encoded format
	"""
	result = codecs.encode(str, 'hex')
	return result

def hex2str(hexnum, intsize=4):
	"""
	Convert a number in hex format to string
	"""
	if not isinstance(hexnum, six.string_types):
		nbits = intsize * 8
		hexnum = "0x%x" % ((hexnum + (1 << nbits)) % (1 << nbits))
	s = hexnum[2:]
	if len(s) % 2 != 0:
		s = "0" + s
	result = codecs.decode(s, 'hex')[::-1]
	return result

def int2hexstr(num, intsize=4):
	"""
	Convert a number to hexified string
	"""
	if intsize == 8:
		if num < 0:
			result = struct.pack("<q", num)
		else:
			result = struct.pack("<Q", num)
	else:
		if num < 0:
			result = struct.pack("<l", num)
		else:
			result = struct.pack("<L", num)
	if '\x00' in result:
		result = result[:result.find('\x00')]
	return result

def list2hexstr(intlist, intsize=4):
	"""
	Convert a list of number/string to hexified string
	"""
	result = ""
	for value in intlist:
		if isinstance(value, str):
			result += value
		else:
			result += int2hexstr(value, intsize)
	return result

def str2intlist(data, intsize=4):
	"""
	Convert a string to list of int
	"""
	result = []
	data = decode_string_escape(data)[::-1]
	l = len(data)
	data = ("\x00" * (intsize - l%intsize) + data) if l%intsize != 0 else data
	for i in range(0, l, intsize):
		if intsize == 8:
			val = struct.unpack(">Q", data[i:i+intsize])[0]
		else:
			val = struct.unpack(">L", data[i:i+intsize])[0]
		result = [val] + result
	return result

@memoized
def format_address(addr, type):
	"""Colorize an address"""
	colorcodes = {
		"data": "blue",
		"code": "red",
		"rodata": "green",
		"value": None
	}
	return colorize(addr, colorcodes[type])

@memoized
def format_reference_chain(chain):
	"""
	Colorize a chain of references
	"""
	v = t = vn = None
	text = ""
	if not chain:
		text += "Cannot access memory address"
	else:
		first = True
		for (v, t, vn) in chain:
			if t != "value":
				text += "%s%s " % ("--> " if not first else "", format_address(v, t))
			else:
				text += "%s%s " % ("--> " if not first else "", v)
			first = False

		if vn:
			text += "(%s)" % vn
		else:
			if v != "0x0":
				s = hex2str(v)
				if is_printable(s, "\x00"):
					text += "(%s)" % string_repr(s.split(b"\x00")[0])
	return text

# vulnerable C functions, source: rats/flawfinder
VULN_FUNCTIONS = [
	"exec", "system", "gets", "popen", "getenv", "strcpy", "strncpy", "strcat", "strncat",
	"memcpy", "bcopy", "printf", "sprintf", "snprintf", "scanf",  "getchar", "getc", "read",
	"recv", "tmp", "temp"
]
@memoized
def format_disasm_code(code, nearby=None):
	"""
	Format output of disassemble command with colors to highlight:
		- dangerous functions (rats/flawfinder)
		- branching: jmp, call, ret
		- testing: cmp, test

	Args:
		- list of tupe (address(Int), code(String), func_offset(String), comment(String))
		- nearby: address for nearby style format (Int)

	Returns:
		- colorized text code (String)
	"""
	colorcodes = {
		"cmp": "red",
		"test": "red",
		"call": "purple",
		"j": "yellow", # jump
		"ret": "blue",
		"push": "lightmagenta",
		"pop": "lightmagenta",
		"mov": "lightcyan",
		"lea": "lightcyan",
	}
	result = ""
	if not code:
		return result

	if nearby is not None:
		target = nearby
	else:
		target = 0

	for line in code:
		color = style = None
		(addr, code, offset, comment) = line
		opcode = re.findall("[a-z]{1,5}", code)[0]
		for c in colorcodes:
			if c in opcode:
				color = colorcodes[c]
				'''
				if c == "call":
					for f in VULN_FUNCTIONS:
						if f in code:
							style = "bold, underline"
							color = "red"
							break
				'''
				break
		if '+' in offset:
			(func,off) = offset.rsplit('+',1)
			offset = yellow(func) + " + " + off
		else:
			offset = yellow(offset)
		prefix = to_hex(addr)
		if addr < target:
			style = "dark"
		elif addr == target:
			style = "bold"
			color = "green"
		#code = 	colorize(line.split(" ")[1], color, style)
		code = 	colorize(code, color, style)
		line = "   %s(%s)"%(cyan(prefix), offset)
		line = line.ljust(90)
		if comment:
			line += "%s(%s)" % ( code, red(comment))
		else:
			line += "%s" % (code)
		result += line + "\n"

	return result.rstrip()+"\n"


def de_bruijn(charset, n, maxlen):
	"""
	Generate the De Bruijn Sequence up to `maxlen` characters for the charset `charset`
	and subsequences of length `n`.
	Algorithm modified from wikipedia http://en.wikipedia.org/wiki/De_Bruijn_sequence
	"""
	k = len(charset)
	a = [0] * k * n
	sequence = []
	def db(t, p):
		if len(sequence) == maxlen:
			return

		if t > n:
			if n % p == 0:
				for j in range(1, p + 1):
					sequence.append(charset[a[j]])
					if len(sequence) == maxlen:
						return
		else:
			a[t] = a[t - p]
			db(t + 1, p)
			for j in range(a[t - p] + 1, k):
				a[t] = j
				db(t + 1, t)
	db(1,1)
	return ''.join(sequence)



@memoized
def cyclic_pattern_offset(value):
	"""
	Search a value if it is a part of cyclic pattern

	Args:
		- value: value to search for (String/Int)

	Returns:
		- offset in pattern if found
	"""
	pattern = cyclic_pattern()
	if to_int(value) is None:
		search = value.encode('utf-8')
	else:
		search = hex2str(to_int(value))

	pos = pattern.find(search)
	return pos if pos != -1 else None

def cyclic_pattern_search(buf):
	"""
	Search all cyclic pattern pieces in a buffer

	Args:
		- buf: buffer to search for (String)

	Returns:
		- list of tuple (buffer_offset, pattern_len, pattern_offset)
	"""
	result = []
	pattern = cyclic_pattern()

	p = re.compile(b"[" + re.escape(to_binary_string(cyclic_pattern_charset())) + b"]{4,}")
	found = p.finditer(buf)
	found = list(found)
	for m in found:
		s = buf[m.start():m.end()]
		i = pattern.find(s)
		k = 0
		while i == -1 and len(s) > 4:
			s = s[1:]
			k += 1
			i = pattern.find(s)
		if i != -1:
			result += [(m.start()+k, len(s), i)]

	return result


def _decode_string_escape_py2(str_):
	"""
	Python2 string escape

	Do not use directly, instead use decode_string.
	"""
	return str_.decode('string_escape')


def _decode_string_escape_py3(str_):
	"""
	Python3 string escape

	Do not use directly, instead use decode_string.
	"""

	# Based on: http://stackoverflow.com/a/4020824
	return codecs.decode(str_, "unicode_escape")


def decode_string_escape(str_):
	"""Generic Python string escape"""
	raise Exception('Should be overriden')


def bytes_iterator(bytes_):
	"""
	Returns iterator over a bytestring. In Python 2, this is just a str. In
	Python 3, this is a bytes.

	Wrap this around a bytestring when you need to iterate to be compatible
	with Python 2 and Python 3.
	"""
	raise Exception('Should be overriden')


def _bytes_iterator_py2(bytes_):
	"""
	Returns iterator over a bytestring in Python 2.

	Do not call directly, use bytes_iterator instead
	"""
	for b in bytes_:
		yield b


def _bytes_iterator_py3(bytes_):
	"""
	Returns iterator over a bytestring in Python 3.

	Do not call directly, use bytes_iterator instead
	"""
	for b in bytes_:
		yield bytes([b])


def bytes_chr(i):
	"""
	Returns a byte string  of length 1 whose ordinal value is i. In Python 2,
	this is just a str. In Python 3, this is a bytes.

	Use this instead of chr to be compatible with Python 2 and Python 3.
	"""
	raise Exception('Should be overriden')


def _bytes_chr_py2(i):
	"""
	Returns a byte string  of length 1 whose ordinal value is i in Python 2.

	Do not call directly, use bytes_chr instead.
	"""
	return chr(i)


def _bytes_chr_py3(i):
	"""
	Returns a byte string  of length 1 whose ordinal value is i in Python 3.

	Do not call directly, use bytes_chr instead.
	"""
	return bytes([i])


def to_binary_string(text):
	"""
	Converts a string to a binary string if it is not already one. Returns a str
	in Python 2 and a bytes in Python3.

	Use this instead of six.b when the text may already be a binary type
	"""
	raise Exception('Should be overriden')


def _to_binary_string_py2(text):
	"""
	Converts a string to a binary string if it is not already one. Returns a str
	in Python 2 and a bytes in Python3.

	Do not use directly, use to_binary_string instead.
	"""
	return str(text)


def _to_binary_string_py3(text):
	"""
	Converts a string to a binary string if it is not already one. Returns a str
	in Python 2 and a bytes in Python3.

	Do not use directly, use to_binary_string instead.
	"""
	if isinstance(text, six.binary_type):
		return text
	elif isinstance(text, six.string_types):
		return six.b(text)
	else:
		raise Exception('only takes string types')


# Select functions based on Python version
if six.PY2:
	decode_string_escape = _decode_string_escape_py2
	bytes_iterator = _bytes_iterator_py2
	bytes_chr = _bytes_chr_py2
	to_binary_string = _to_binary_string_py2
elif six.PY3:
	decode_string_escape = _decode_string_escape_py3
	bytes_iterator = _bytes_iterator_py3
	bytes_chr = _bytes_chr_py3
	to_binary_string = _to_binary_string_py3
else:
	raise Exception("Could not identify Python major version")


def dbg_print_vars(*args):
	"""Prints name and repr of each arg on a separate line"""
	import inspect
	parent_locals = inspect.currentframe().f_back.f_locals
	maps = []
	for arg in args:
		for name, value in parent_locals.items():
			if id(arg) == id(value):
				maps.append((name, repr(value)))
				break
	print('\n'.join(name + '=' + value for name, value in maps))


def string_repr(text, show_quotes=True):
	"""
	Prints the repr of a string. Eliminates the leading 'b' in the repr in
	Python 3.

	Optionally can show or include quotes.
	"""
	if six.PY3 and isinstance(text, six.binary_type):
		# Skip leading 'b' at the beginning of repr
		output = repr(text)[1:]
	else:
		output = repr(text)

	if show_quotes:
		return output
	else:
		return output[1:-1]

def error_msg(text):
	wprint("[ERROR] %s" % text, "lightred")
	print("")

def pager(text, pagesize=12):
	"""
	Paging output, mimic external command less/more
	"""
	if pagesize <= 0:
		cprint(text)
		return

	i = 1
	text = text.splitlines()
	l = len(text)

	for line in text:
		cprint(line+"\n")
		if i % pagesize == 0:
			ans = input("--More--(%d/%d)" % (i, l))
			if ans.lower().strip() == "q":
				break
		i += 1

	return
