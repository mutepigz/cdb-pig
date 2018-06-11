# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
import pykd
import os
import sys
import pykd
import re
import string
import random
from time import time

VERSION = "0.1"
FILEPATH = os.path.abspath(sys.argv[0])
while os.path.islink(FILEPATH):
	FILEPATH = os.readlink(FILEPATH)
sys.path.insert(0, os.path.dirname(FILEPATH))
sys.path.insert(0, os.path.dirname(FILEPATH) + "/lib/")

from logo import logos
from color import cprint,wprint,debug
from utils import *


def validate_target(func, *args, **kwargs):
	"""
	A decorator that ensures that the specified target_id exists and
	is valid.

	Expects the target ID to be either the 'target_id' param in kwargs,
	or the first positional parameter.

	Raises a NoSuchTargetException if the target does not exist.
	"""
	def inner(self, *args, **kwargs):
		# find the target param
		target_id = None
		if 'target_id' in kwargs and kwargs['target_id'] != None:
			target_id = kwargs['target_id']
		else:
			target_id = 0

		# if there was a target specified, check that it's valid
		if not self.target_is_valid(target_id):
			raise NoSuchTargetException()

		# call the function
		return func(self, *args, **kwargs)
	return inner


def validate_busy(func, *args, **kwargs):
	"""
	A decorator that raises an exception if the specified target is busy.

	Expects the target ID to be either the 'target_id' param in kwargs,
	or the first positional parameter.

	Raises a TargetBusyException if the target does not exist.
	"""
	def inner(self, *args, **kwargs):
		# find the target param
		target_id = None
		if 'target_id' in kwargs and kwargs['target_id'] != None:
			target_id = kwargs['target_id']
		else:
			target_id = 0

		# if there was a target specified, ensure it's not busy
		if self.target_is_busy(target_id):
			raise TargetBusyException()

		# call the function
		return func(self, *args, **kwargs)
	return inner

class DebuggerAdaptor(object):
	"""
	Base debugger adaptor class. Debugger adaptors implemented in plugins for
	specific debuggers inherit from this.
	"""

	reg_names = {
		"x86":	  {"pc": "eip", "sp": "esp"},
		"x86_64":   {"pc": "rip", "sp": "rsp"},
	}
	REGISTERS = {
	8 : ["al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"],
	16: ["ax", "bx", "cx", "dx"],
	32: ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"],
	64: ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip",
		 "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
	}
	cs_archs = {}

	def __init__(self, *args, **kwargs):
		self.listeners = []
		self.command = WinDbgCommand()

	def target_exists(self, target_id=0):
		"""
		Returns True or False indicating whether or not the specified
		target is present and valid.

		`target_id` is a target ID (or None for the first target)
		"""
		try:
			target = self._target(target_id=target_id)
		except Exception as e:
			return False
		return target is not None

	def target_is_valid(self, target_id=0):
		"""
		Returns True or False indicating whether or not the specified
		target is present and valid.

		`target_id` is a target ID (or None for the first target)
		"""
		try:
			target = self._target(target_id=target_id)
		except:
			return False
		return target['state'] != "invalid"

	def target_is_busy(self, target_id=0):
		"""
		Returns True or False indicating whether or not the specified
		target is busy.

		`target_id` is a target ID (or None for the first target)
		"""
		try:
			target = self._target(target_id=target_id)
		except:
			raise NoSuchTargetException()
		return target['state'] == "running"

	def add_listener(self, callback, state_changes=["stopped"]):
		"""
		Add a listener for state changes.
		"""
		self.listeners.append({"callback": callback, "state_changes": state_changes})

	def remove_listener(self, callback):
		"""
		Remove a listener.
		"""
		listeners = filter(lambda x: x['callback'] == callback, self.listeners)
		for l in listeners:
			self.listeners.remove(l)

	def update_state(self):
		"""
		Notify all the listeners (probably `wait` plugins) that the state
		has changed.

		This is called by the debugger's stop-hook.
		
		"""
		self.context()
		self.watch()

	def register_command_plugin(self, name, cls):
		pass

	def capabilities(self):
		"""
		Return a list of the debugger's capabilities.

		Thus far only the 'async' capability is supported. This indicates
		that the debugger host can be queried from a background thread,
		and that views can use non-blocking API requests without queueing
		requests to be dispatched next time the debugger stops.
		"""
		return []

	def pc(self, target_id=0, thread_id=None):
		return self.program_counter(target_id, thread_id)

	def sp(self, target_id=0, thread_id=None):
		return self.stack_pointer(target_id, thread_id)


class DebuggerCommand (object):
	"""
	The `voltron` command in the debugger.
	"""
	def __init__(self, *args, **kwargs):
		super(DebuggerCommand, self).__init__(*args, **kwargs)
		self.adaptor = WinDbgAdaptor()
		self.registered = False

	def handle_command(self, command):
		global log
		if 'debug' in command:
			if 'enable' in command:
				print("Debug logging enabled")
			elif 'disable' in command:
				print("Debug logging disabled")
		elif 'init' in command:
			self.register_hooks()
		elif 'stopped' in command or 'update' in command:
			self.adaptor.update_state()

class WinDbgAdaptor(DebuggerAdaptor):
	sizes = {
		'x86': 4,
		'x86_64': 8,
	}
	max_deref = 24
	max_string = 128
	def __init__(self, *args, **kwargs):
		self.listeners = []
		self.host = pykd

	def version(self):
		"""
		Get the debugger's version.

		Returns a string containing the debugger's version
		(e.g. 'Microsoft (R) Windows Debugger Version whatever, pykd 0.3.0.38')
		"""
		try:
			[windbg] = [line for line in pykd.dbgCommand('version').split('\n') if 'Microsoft (R) Windows Debugger Version' in line]
		except:
			windbg = 'WinDbg <unknown>'
		return '{}, {}'.format(windbg, 'pykd {}'.format(pykd.version))

	def _target(self, target_id=0):
		"""
		Return information about the specified target.

		Returns data in the following structure:
		{
			"id":	   0,		 # ID that can be used in other funcs
			"file":	 "/bin/ls", # target's binary file
			"arch":	 "x86_64",  # target's architecture
			"state:	 "stopped"  # state
		}
		"""
		# get target properties
		d = {}
		d["id"] = pykd.getCurrentProcessId()
		d["num"] = d['id']

		# get target state
		d["state"] = self._state()

		d["file"] = pykd.getProcessExeName()

		# get arch
		d["arch"] = self.get_arch()
		d['byte_order'] = self.get_byte_order()
		d['addr_size'] = self.get_addr_size()
		d['bits'] = d['addr_size'] << 3

		return d

	def target(self, target_id=0):
		"""
		Return information about the current inferior.

		We only support querying the current inferior with WinDbg.

		`target_id` is ignored.
		"""
		return self._target()

	def targets(self, target_ids=None):
		"""
		Return information about the debugger's current targets.

		`target_ids` is ignored. Only the current target is returned. This
		method is only implemented to maintain API compatibility with the
		LLDBAdaptor.
		"""
		return [self._target()]

	@validate_target
	def state(self, target_id=0):
		"""
		Get the state of a given target.
		"""
		return self._state()

	@validate_busy
	@validate_target
	def watch(self):
		"""
		Show the memory by watch_command.
		"""
		watch_command = get_alias("watch_command")
		if watch_command:
			wprint("[%s]" % "memory".center(150, "-"),"lightblue")
			if 'last_watch' not in dir(self):
				self.last_watch = ''
			(dc, addr, num) = watch_command.strip().split()
			now_watch = self.dumpmem(to_int(addr), int(num), dc)
			self.watch_show(to_int(addr), now_watch, self.last_watch)
			self.last_watch = now_watch

	@validate_busy
	@validate_target
	def registers(self, target_id=0, thread_id=None, registers=[]):
		"""
		Get the register values for a given target/thread.
		"""
		arch = self.get_arch()

		# if we got 'sp' or 'pc' in registers, change it to whatever the right name is for the current arch
		if arch in self.reg_names:
			if 'pc' in registers:
				registers.remove('pc')
				registers.append(self.reg_names[arch]['pc'])
			if 'sp' in registers:
				registers.remove('sp')
				registers.append(self.reg_names[arch]['sp'])
		else:
			raise Exception("Unsupported architecture: {}".format(target['arch']))

		# get registers
		if registers != []:
			vals = {}
			for reg in registers:
				vals[reg] = pykd.reg(reg)
		else:
			if arch == "x86_64":
				reg_names = ['rax', 'rbx', 'rcx', 'rdx', 'rbp', 'rsp', 'rdi', 'rsi', 'rip', 'r8', 'r9', 'r10',
							 'r11', 'r12', 'r13', 'r14', 'r15', 'cs', 'ds', 'es', 'fs', 'gs', 'ss']
			elif arch == "x86":
				reg_names = ['eax', 'ebx', 'ecx', 'edx', 'ebp', 'esp', 'edi', 'esi', 'eip', 'cs', 'ds', 'es',
							 'fs', 'gs', 'ss']
			else:
				raise UnknownArchitectureException()

			vals = {}
			for reg in reg_names:
				try:
					vals[reg] = pykd.reg(reg)
				except:
					vals[reg] = 'N/A'

			# Get flags
			try:
				vals['rflags'] = pykd.reg(reg)
			except:
				vals['rflags'] = 'N/A'

			# Get SSE registers
			try:
				vals.update(self.get_registers_sse(16))
			except:
				pass
			# Get FPU registers
			try:
				vals.update(self.get_registers_fpu())
			except:
				pass

		return vals

	def watch_show(self, base_addr, now, last='', count=0x8):
		line = 0
		n = 0
		step = self._target()['addr_size']
		for idx,n in enumerate(now):
			if idx%count == 0 :
				print("")
				wprint(to_hex(base_addr+line*count)+"  ","cyan")
			if idx<len(last) and last[idx]!=n:
				wprint(just_hex(n, step<<1), "lightred")
			else:
				wprint(just_hex(n, step<<1))
			wprint(" ")
			line+=1
		print("")

	def get_reg(self, regname=''):
		if not regname:
			return self.registers()
		
		reg = pykd.dbgCommand("r %s"%regname)
		if reg:
			return to_int(reg.split('=')[1])
		else:
			return None

	@validate_busy
	@validate_target
	def stack_pointer(self, target_id=0, thread_id=None):
		"""
		Get the value of the stack pointer register.
		"""
		arch = self.get_arch()
		if arch in self.reg_names:
			sp_name = self.reg_names[arch]['sp']
			sp = pykd.reg(sp_name)
		else:
			raise UnknownArchitectureException()

		return sp_name, sp

	@validate_busy
	@validate_target
	def program_counter(self, target_id=0, thread_id=None):
		"""
		Get the value of the program counter register.
		"""
		arch = self.get_arch()
		if arch in self.reg_names:
			pc_name = self.reg_names[arch]['pc']
			pc = pykd.reg(pc_name)
		else:
			raise UnknownArchitectureException()

		return pc_name, pc

	@validate_busy
	@validate_target
	def memory(self, address, length, target_id=0):
		"""
		Get the register values for .

		`address` is the address at which to start reading
		`length` is the number of bytes to read
		"""
		# read memory
		memory = array.array('B', pykd.loadBytes(address, length)).tostring()

		return memory

	@validate_busy
	@validate_target
	def stack(self, length=10, target_id=0, thread_id=None):
		"""
		Get the register values for .

		`length` is the number of bytes to read
		`target_id` is a target ID (or None for the first target)
		`thread_id` is a thread ID (or None for the selected thread)
		"""
		# get the stack pointer
		sp_name, sp = self.stack_pointer(target_id=target_id, thread_id=thread_id)

		# read memory
		memory = self.memory(sp, length, target_id=target_id)

		return memory

	@validate_busy
	@validate_target
	def disassemble(self, target_id=0, address=None, count=12):
		"""
		Get a disassembly of the instructions at the given address.

		`address` is the address at which to disassemble. If None, the
		current program counter is used.
		`count` is the number of instructions to disassemble.
		"""
		# make sure we have an address
		if address is None:
			pc_name, address = self.program_counter(target_id=target_id)

		# disassemble
		output = pykd.dbgCommand('u 0x{:x} l{}'.format(address, count))

		return output

	@validate_busy
	@validate_target
	def dereference(self, pointer, target_id=0):
		"""
		Recursively dereference a pointer for display
		"""
		fmt = ('<' if self.get_byte_order() == 'little' else '>') + {2: 'H', 4: 'L', 8: 'Q'}[self.get_addr_size()]

		addr = pointer
		chain = []

		# recursively dereference
		for i in range(0, self.max_deref):
			try:
				[ptr] = pykd.loadPtrs(addr, 1)
				if ptr in chain:
					break
				chain.append(('pointer', addr))
				addr = ptr
			except:
				break

		# get some info for the last pointer
		# first try to resolve a symbol context for the address
		if len(chain):
			p, addr = chain[-1]
			output = pykd.findSymbol(addr)
			sym = True
			try:
				# if there's no symbol found, pykd returns a hex string of the address
				if int(output, 16) == addr:
					sym = False
			except:
				pass

			if sym:
				chain.append(('symbol', output.strip()))
			else:
				mem = pykd.loadBytes(addr, 2)
				if mem[0] < 127:
					if mem[1] == 0:
						a = []
						for i in range(0, self.max_string, 2):
							mem = pykd.loadBytes(addr + i, 2)
							if mem == [0, 0]:
								break
							a.extend(mem)
						output = array.array('B', a).tostring().decode('UTF-16').encode('latin1')
						chain.append(('unicode', output))
					else:
						output = pykd.loadCStr(addr)
						chain.append(('string', output))

		return chain

	def command(self, command=None):
		"""
		Execute a command in the debugger.

		`command` is the command string to execute.
		"""
		if command:
			res = pykd.dbgCommand(command)
		else:
			raise Exception("No command specified")

		return res

	def disassembly_flavor(self):
		"""
		Return the disassembly flavor setting for the debugger.

		Returns 'intel' or 'att'
		"""
		return 'intel'

	def breakpoints(self, target_id=0):
		"""
		Return a list of breakpoints.

		Returns data in the following structure:
		[
			{
				"id":		   1,
				"enabled":	  True,
				"one_shot":	 False,
				"hit_count":	5,
				"locations": [
					{
						"address":  0x100000cf0,
						"name":	 'main'
					}
				]
			}
		]
		"""
		breakpoints = []

		for i in range(0, pykd.getNumberBreakpoints()):
			b = pykd.getBp(i)
			addr = b.getOffset()

			name = hex(addr)
			try:
				name = pykd.findSymbol(addr)
			except:
				pass

			breakpoints.append({
				'id':		   i,
				'enabled':	  True,
				'one_shot':	 False,
				'hit_count':	'-',
				'locations':	[{
					"address":  addr,
					"name":	 name
				}]
			})

		return breakpoints

	def capabilities(self):
		"""
		Return a list of the debugger's capabilities.

		Thus far only the 'async' capability is supported. This indicates
		that the debugger host can be queried from a background thread,
		and that views can use non-blocking API requests without queueing
		requests to be dispatched next time the debugger stops.
		"""
		return ['async']

	#
	# Private functions
	#

	def _state(self):
		"""
		Get the state of a given target. Internal use.
		"""
		s = pykd.getExecutionStatus()
		if s == pykd.executionStatus.Break:
			state = 'stopped'
		elif s == pykd.executionStatus.Go:
			state = 'running'
		else:
			state = 'invalid'

		return state

	def get_registers_sse(self, num=8):
		regs = {}
		for i in range(0, 16):
			try:
				reg = 'xmm{}'.format(i)
				regs[reg] = pykd.reg(reg)
			except:
				break
		return regs

	def get_registers_fpu(self):
		regs = {}
		for i in range(0, 8):
			try:
				reg = 'st{}'.format(i)
				regs[reg] = pykd.reg(reg)
			except:
				break
		return regs

	def get_next_instruction(self):
		return str(pykd.disasm())

	def get_arch(self):
		#t = pykd.getCPUType()
		t = pykd.getRegisterName(5)
		#if t == pykd.CPUType.I386:
		if t[0] == 'e':
			return 'x86'
		else:
			return 'x86_64'
		return arch

	def get_addr_size(self):
		arch = self.get_arch()
		return self.sizes[arch]

	def get_byte_order(self):
		return 'little'

	def _get_perm(self, perm):
		if perm == "PAGE_NOACCESS":
			perm = "---"
		elif perm == "PAGE_READONLY":
			perm = "r--"
		elif perm == "PAGE_WRITECOPY" or "PAGE_READWRITE" in perm:
			perm = "rw-"
		elif perm == "PAGE_EXECUTE_READ":
			perm = "r-x"
		elif perm == "PAGE_EXECUTE_READWRITE ":
			perm = "rwx"
		elif perm == "PAGE_EXECUTE ":
			perm = "--x"
		return perm

	@memoized
	def _get_vmmap(self):
		try:
			pykd.dbgCommand("!address").split("---\n")[1]
			vmmap = pykd.dbgCommand("!address").split("---\n")[1]
		except:
			vmmap = ''
		if not vmmap:
			return [(0,0xffffffffffffffff,0xffffffffffffffff,0,0,"rwx","NONAME")]
		result = []
		pattern = re.compile("([0-9a-f`]*) *([0-9a-f`]*) *([0-9a-f`]*) *(MEM_[A-Z]*) *(MEM_[A-Z]*) *(PAGE_[_A-Z]*) *(.*?)\n")
		matches = pattern.findall(vmmap)
		if matches:
			for (start, end, size, type, state, perm, mapname) in matches:
				start = to_int(start.strip())
				end = to_int(end.strip())
				size = size.strip()
				perm = perm.strip()
				mapname = mapname.strip()
				perm = self._get_perm(perm)

				result += [(start, end, size, type, state, perm, mapname)]
		return result

	def get_vmmap(self):
		try:
			if self.vmmap:
				return self.vmmap
		except:
			self.vmmap = self._get_vmmap()
			return self.vmmap

	@memoized
	def get_vmrange(self, address):
		"""
		Get virtual memory mapping range of an address

		Args:
			- address: target address (Int)

		Returns:
			- tuple of virtual memory info (start, end, perm, mapname)
		"""
		if address is None:
			return None	
		try:
			vmitem = pykd.dbgCommand("!vprot %s" % to_hex(address))
		except:
			return (0, 0, '', '', '', '---', '')

		if not vmitem or "BaseAddress" not in vmitem or "RegionSize" not in vmitem or "Protect" not in vmitem:
			return (0, 0, '', '', '', '---', '')
			'''
			vmitem = pykd.dbgCommand("!address %s" % to_hex(address))
			if not vmitem or "Base Address" not in vmitem or "Region Size" not in vmitem or "Protect" not in vmitem:
				return None
			'''

		perm = ''
		vmitem = vmitem.splitlines()
		for line in vmitem:
			if line.startswith("BaseAddress") or line.startswith("Base Address"):
				start = to_int(re.findall("[0-9a-f`]*", line)[0])
			if line.startswith("RegionSize") or line.startswith("Region Size"):
				size = to_int(re.findall("[0-9a-f`]*", line)[0])
			if line.startswith("Protect"):
				perm = re.findall("PAGE_[_A-Z]*", line)
				if perm and "GUARD" not in line:
					perm = self._get_perm(perm[0])
				else:
					perm = '---'
		if not perm:
			perm = '---'
		return (start, size, '', '', '', perm, '')

	@memoized
	def is_executable(self, address):
		"""
		Check if an address is executable

		Args:
			- address: target address (Int)
			- maps: only check in provided maps (List)

		Returns:
			- True if address belongs to an executable address range (Bool)
		"""
		vmrange = self.get_vmrange(address)
		if vmrange and "x" in vmrange[5]:
			return True
		else:
			return False

	@memoized
	def is_writable(self, address):
		"""
		Check if an address is writable

		Args:
			- address: target address (Int)
			- maps: only check in provided maps (List)

		Returns:
			- True if address belongs to a writable address range (Bool)
		"""
		vmrange = self.get_vmrange(address)
		if vmrange and "w" in vmrange[5]:
			return True
		else:
			return False

	@memoized
	def is_address(self, value):
		"""
		Check if a value is a valid address (belongs to a memory region)

		Args:
			- value (Int)
			- maps: only check in provided maps (List)

		Returns:
			- True if value belongs to an address range (Bool)
		"""
		vmrange = self.get_vmrange(value)
		return (vmrange is not None) and vmrange[5]!='---'

	def get_disasm(self, address):
		"""
		Get the ASM code of instruction at address

		Args:
			- address: address to read instruction (Int)

		Returns:
			- asm code (String)
		"""
		if not address:
			return (None, None)
		code = pykd.dbgCommand("u %s L1" % (to_hex(address)))
		if code:
			codeline = code.split("\n")
			func = codeline[0].strip()
			
			if re.match("^.*?:$",func):
				func = func[:-1]
			else:
				return (None, None)
			disasm = re.findall("[0-9a-f]{8} [0-9a-f]* *(.*?)$",codeline[1])[0]
			return (func, disasm)
		else:
			return (None, None)

	@memoized
	def examine_mem_reference(self, value, depth=4):
		"""
		Deeply examine a value in memory for its references

		Args:
			- value: value to examine (Int)

		Returns:
			- list of tuple of (value(Int), type(String), next_value(Int))
		"""
		result = []
		if depth <= 0:
			depth = 0xffffffff
		(v, t, vn) = self.examine_mem_value(value)
		if not vn:
			result += [(v, t, vn)]

		while vn:
			if len(result) > depth:
				_v, _t, _vn = result[-1]
				result[-1] = (_v, _t, "--> ...")
				break

			result += [(v, t, vn)]

			if v == vn or to_int(v) == to_int(vn): # point to self
				break
			if to_int(vn) is None:
				break
			if to_int(vn) in [to_int(v) for (v, _, _) in result]: # point back to previous value
				result[-1] = (v,t,vn+"(head)")
				break
			(v, t, vn) = self.examine_mem_value(to_int(vn))


		return result

	@memoized
	def examine_mem_value(self, value):
		"""
		Examine a value in memory for its type and reference

		Args:
			- value: value to examine (Int)

		Returns:
			- tuple of (value(Int), type(String), next_value(String))
		"""
		def examine_data(value, bits=32):
			out = pykd.dbgCommand("d%s %s" % ("q" if bits == 64 else "d", to_hex(value)))
			if out:
				out = out.split("  ",1)[1].split(" ",1)[0].strip()
			step = int(bits//8)

			if '????' not in out and is_printable(int2hexstr(to_int(out), step)):
				str = pykd.dbgCommand("da %s"%to_hex(value))
				if str:
					str = str.split("  ",1)[1].strip()
					return str
			return out
		if value is None:
			return [0, '', '']

		if not self.is_address(value): # a value
			result = (to_hex(value), "value", "")
			return result

		bits = self._target()['bits']
		# check for writable first so rwxp mem will be treated as data
		if self.is_writable(value): # writable data address
			out = examine_data(value, bits)
			if out:
				result = (to_hex(value), "data", out)

		elif self.is_executable(value): # code/rodata address
			(func,disasm) = self.get_disasm(value)
			if func and disasm:
				result = (to_hex(value), "code", "(%s : %s)" % (yellow(func),purple(disasm)))
			else:
				out = examine_data(value, bits)
				result = (to_hex(value), "data", out)

		else: # readonly data address
			out = examine_data(value, bits)
			if out:
				result = (to_hex(value), "rodata", out)
			else:
				result = (to_hex(value), "rodata", "MemError")

		return result

	def telescope(self, address, count=10):
		"""
		Display memory content at an address with smart dereferences
		Usage:
			MYNAME [linecount] (analyze at current $SP)
			MYNAME address [linecount]
		"""

		step = self._target()['addr_size']
		if not self.is_address(address): # cannot determine address
			wprint("Invalid address: 0x%x"%address, "lightred", "black", 1)
			return
			for i in range(count):
				if not pykd.dbgCommand("d%s %s" % ("q" if step == 8 else "d", hex(address + i*step))):
					break
			return
		result = []
		for i in range(count):
			value = address + i*step
			if self.is_address(value):
				result += [self.examine_mem_reference(value)]
			else:
				result += [None]

		idx = 0
		text = ""

		for chain in result:
			text += "%04d| " % (idx)
			text += format_reference_chain(chain)
			text += "\n"
			idx += step

		pager(text)

		return

	def dumpmem(self, start, count=0, dc=''):
		result = []
		step = self._target()['addr_size']
		if not dc:
			dc = "d%s" % ("q" if step == 8 else "d")
		if count is not None:
			ret = pykd.dbgCommand("%s %s" % (dc, to_hex(start)))
			if not ret:
				error_msg("dump memory failed")
			else:
				lines = ret.strip().splitlines()
				for line in lines:
					for mem in line.split()[1:]:
						result.append(to_int(mem))

		if  result:
			return result[:count]
		else:
			return result

	def _get_function_args_32(self, code, argc=None):
		"""
		Guess the number of arguments passed to a function - i386
		"""
		if not argc:
			argc = 0
			p = re.compile("\s*mov.*\[esp(.*)\],")
			matches = p.findall(code)
			if matches:
				l = len(matches)
				for v in matches:
					if v.startswith("+"):
						offset = to_int(v[1:])
						if offset is not None and (offset//4) > l:
							continue
					argc += 1
			else: # try with push style
				argc = code.count("push")

		argc = min(argc, 6)
		if argc == 0:
			return []
		sp = self.sp()[1]
		args = self.dumpmem(sp, argc)

		return args

	def _get_function_args_64(self, code, argc=None):
		"""
		Guess the number of arguments passed to a function - x86_64
		"""

		# just retrieve max 6 args
		arg_order = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
		p = re.compile("\s*([^ ]*)\s*(.*),")
		matches = p.findall(code)
		regs = [r for (_, r) in matches]
		p = re.compile(("di|si|dx|cx|r8|r9"))
		m = p.findall(" ".join(regs))
		m = list(set(m)) # uniqify
		argc = 0
		if "si" in m and "di" not in m: # dirty fix
			argc += 1
		argc += m.count("di")
		if argc > 0:
			argc += m.count("si")
		if argc > 1:
			argc += m.count("dx")
		if argc > 2:
			argc += m.count("cx")
		if argc > 3:
			argc += m.count("r8")
		if argc > 4:
			argc += m.count("r9")

		if argc == 0:
			return []

		args = []
		regs = self.registers()
		for i in range(argc):
			args += [regs[arg_order[i]]]

		return args

	def get_function_args(self, argc=None):
		"""
		Get the guessed arguments passed to a function when stopped at a call instruction

		Args:
			- argc: force to get specific number of arguments (Int)

		Returns:
			- list of arguments (List)
		"""

		args = []
		regs = self.registers()
		if regs is None:
			return []

		arch = self.get_arch()
		pc = self.pc()[1]
		prev_insts = self.prev_inst(pc, 12)

		code = ""
		if not prev_insts:
			return []
		for (addr, inst, offset, comment) in prev_insts[::-1]:
			code = "%s\n" % (inst) + code

		if "86" in arch:
			args = self._get_function_args_32(code, argc)
		if "64" in arch:
			args = self._get_function_args_64(code, argc)
		return args

	def dumpargs(self, *arg):
		"""
		Display arguments passed to a function when stopped at a call instruction
		Usage:
			MYNAME [count]
				count: force to display "count args" instead of guessing
		"""

		(count,) = normalize_argv(arg, 1)

		args = self.get_function_args(count)
		if args:
			print("Guessed arguments:")
			for (i, a) in enumerate(args):
				chain = self.examine_mem_reference(a)
				cprint("arg[%d]: %s" % (i, format_reference_chain(chain))+"\n")
		else:
			print("No argument")

		return

	@memoized
	def prev_inst(self, address, count=1):
		"""
		Get previous instructions at an address

		Args:
			- address: address to get previous instruction (Int)
			- count: number of instructions to read (Int)

		Returns:
			- list of tuple (address(Int), code(String), func_offset(String), comment(String))
		"""
		code = pykd.dbgCommand("ub %s L%s" % (to_hex(address), to_hex(count)))

		if not code: 
			return []

		result = []
		lines = code.splitlines()
		for line in lines:
			addr = line.split(" ", 1)[0]
			addr = to_int(addr)
			(func, code) = self.get_disasm(addr)
			if not func or not code:
				continue 
			result += [(addr, code, func,'')]
		return result

	def disassemble_around(self, address, count=14, jump=0, prev=1):
		"""
		Disassemble instructions nearby current PC or an address

		Args:
			- address: start address to disassemble around (Int)
			- count: number of instructions to disassemble
			- jump : jump from address or not(-1:not take jump; 0: no jump; 1: take jump)
			- prev : need prev_code or not 

		Returns:
			- list of tupe (address(Int), code(String), func_offset(String), comment(String))
		"""
		count = min(count, 256)
		pc = address
		if pc is None:
			return None

		# check if address is reachable
		if not self.is_address(pc) or not pykd.dbgCommand("u %s" % (to_hex(pc))):
			return None

		if prev:
			prev_code = self.prev_inst(pc, count//2)
		else:
			prev_code = []

		now_code = []
		code = pykd.dbgCommand("u %s L%s" % (to_hex(pc), to_hex(count//2+1)))
		hex_addr = "%x" % pc
		if len(hex_addr) > 8:
			hex_addr = "%s`%s" % (hex_addr[:-8], hex_addr[-8:])

		if code and hex_addr in code:
			lines = code.splitlines()
			if "???" not in code:
				for line in lines:
					addr = line.split(" ", 1)[0]
					comment = ""
					if hex_addr in addr:
						if jump==1:
							comment = "JUMP is taken"
						elif jump==-1:
							comment = "JUMP is NOT taken"
					addr = to_int(addr)
					(func, code) = self.get_disasm(addr)
					if not func or not code:
						continue
					now_code += [(addr, code, func, comment)]
			else:
				error_msg("The address is not available.")

		return prev_code + now_code

	def get_eflags(self):
		"""
		Get flags value from EFLAGS register

		Returns:
			- dictionary of named flags
		"""

		# Eflags bit masks, source vdb
		EFLAGS_CF = 1 << 0
		EFLAGS_PF = 1 << 2
		EFLAGS_AF = 1 << 4
		EFLAGS_ZF = 1 << 6
		EFLAGS_SF = 1 << 7
		EFLAGS_TF = 1 << 8
		EFLAGS_IF = 1 << 9
		EFLAGS_DF = 1 << 10
		EFLAGS_OF = 1 << 11

		flags = {"CF":0, "PF":0, "AF":0, "ZF":0, "SF":0, "TF":0, "IF":0, "DF":0, "OF":0}
		eflags = self.get_reg("efl")
		if not eflags:
			return None
		flags["CF"] = bool(eflags & EFLAGS_CF)
		flags["PF"] = bool(eflags & EFLAGS_PF)
		flags["AF"] = bool(eflags & EFLAGS_AF)
		flags["ZF"] = bool(eflags & EFLAGS_ZF)
		flags["SF"] = bool(eflags & EFLAGS_SF)
		flags["TF"] = bool(eflags & EFLAGS_TF)
		flags["IF"] = bool(eflags & EFLAGS_IF)
		flags["DF"] = bool(eflags & EFLAGS_DF)
		flags["OF"] = bool(eflags & EFLAGS_OF)

		return flags

	def testjump(self, inst=None):
		"""
		Test if jump instruction is taken or not

		Returns:
			- (status, address of target jumped instruction)
		"""

		flags = self.get_eflags()
		if not flags:
			return None

		if not inst:
			pc = self.pc()[1]
			(_, inst) = self.get_disasm(pc)
			if not inst:
				return None

		opcode = re.findall("[a-z]{1,5}", inst)[0]
		next_addr = re.findall("\([0-9a-f`]*\)", inst.split()[-1])[0][1:-1]
		if next_addr is None:
			next_addr = 0
		else:
			next_addr = to_int(next_addr)
		
		if opcode == "jmp":
			return next_addr
		if opcode == "je" and flags["ZF"]:
			return next_addr
		if opcode == "jne" and not flags["ZF"]:
			return next_addr
		if opcode == "jg" and not flags["ZF"] and (flags["SF"] == flags["OF"]):
			return next_addr
		if opcode == "jge" and (flags["SF"] == flags["OF"]):
			return next_addr
		if opcode == "ja" and not flags["CF"] and not flags["ZF"]:
			return next_addr
		if opcode == "jae" and not flags["CF"]:
			return next_addr
		if opcode == "jl" and (flags["SF"] != flags["OF"]):
			return next_addr
		if opcode == "jle" and (flags["ZF"] or (flags["SF"] != flags["OF"])):
			return next_addr
		if opcode == "jb" and flags["CF"]:
			return next_addr
		if opcode == "jbe" and (flags["CF"] or flags["ZF"]):
			return next_addr
		if opcode == "jo" and flags["OF"]:
			return next_addr
		if opcode == "jno" and not flags["OF"]:
			return next_addr
		if opcode == "jz" and flags["ZF"]:
			return next_addr
		if opcode == "jnz" and flags["OF"]:
			return next_addr

		return None

	@validate_busy
	@validate_target
	def context(self,target_id=0):
		wprint("[%s]" % "CDB-PIG".center(150, "-"),"lightred","black",1)
		self.context_register()
		self.context_code()
		self.context_stack()

	@validate_busy
	@validate_target
	def context_register(self,target_id=0):
		wprint("[%s]" % "registers".center(150, "-"),"lightblue","black",1)
		#text = ""
		def get_reg_text(r, v):
			text = green("%s" % r.upper().ljust(3)) + ": "
			chain = self.examine_mem_reference(v)
			text += format_reference_chain(chain)
			text += "\n" 
			return text 
		regs = self.registers()
		bits = self._target()['bits']
		text = ''
		for r in self.REGISTERS[bits]:
			if r in regs:
				text += (get_reg_text(r, regs[r]))
		cprint(text)
		return

	def context_code(self, pc='', count = 14):
		"""
		Display nearby disassembly at $PC of current execution context
		Usage:
			MYNAME [linecount]
		"""

		if not pc:
			pc = self.pc()[1]
		if self.is_address(pc):
			(func,inst) = self.get_disasm(pc)
		else:
			(func,inst) = (None, None)

		wprint("[%s]" % "disassemble".center(150, "-"),"lightblue","black",1)
		if inst: # valid $PC
			text = []
			opcode = inst.split("\t")[-1].split()[0].strip()

			# stopped at function call
			if "call" in opcode:
				text += self.disassemble_around(pc, count)
				cprint(format_disasm_code(text, pc))
				self.dumpargs()
			# stopped at jump
			elif "j" in opcode:
				jumpto = self.testjump(inst)
				if jumpto: # JUMP is taken
					text += self.disassemble_around(pc, count, 1)
					for i,k in enumerate(text):
						if k[0] == pc:
							break
					cprint(format_disasm_code(text[:i+1], pc))
					jtext = self.disassemble_around(jumpto, count-1, 0, 0)
					wprint("===> jump to\n","red")
					if not jtext:
						wprint("   Cannot evaluate jump destination\n","red")
					else:
						cprint(format_disasm_code(jtext, jumpto))
				else: # JUMP is NOT taken
					text += self.disassemble_around(pc, count, -1)
					cprint(format_disasm_code(text, pc))
			# stopped at other instructions
			else:
				text += self.disassemble_around(pc, count)
				cprint(format_disasm_code(text, pc))
		else: # invalid $PC
			wprint("Invalid $PC address: 0x%x" % pc, "red", "black", 1)

		return

	@validate_busy
	@validate_target
	def context_stack(self,count=10):
		wprint("[%s]" % "stack".center(150, "-"),"lightblue","black",1)
		text = ""
		nowsp = self.sp()[1]
		if self.is_address(nowsp):
			self.telescope(nowsp, count)
		else:
			wprint("Invalid $SP address: 0x%x"%nowsp, "lightred", "black", 1)
		return

class EventHandler(pykd.eventHandler):
	"""
	Event handler for WinDbg/PyKD events.
	"""
	def __init__(self, adaptor, *args, **kwargs):
		super(EventHandler, self).__init__(*args, **kwargs)
		self.adaptor = adaptor

	def onExecutionStatusChange(self, status):
		if status == pykd.executionStatus.Break:
			self.adaptor.update_state()


class WinDbgCommand(DebuggerCommand):
	"""
	Debugger command class for WinDbg
	"""
	def __init__(self):
		super(WinDbgCommand, self).__init__()
		self.register_hooks()

	def invoke(self, debugger, command, result, dict):
		self.handle_command(command)

	def register_hooks(self):
		self.handler = EventHandler(self.adaptor)

	def unregister_hooks(self):
		del self.handler
		self.handler = None

from lib.utils import *

def set_alias(name, value):
	pykd.dbgCommand("as %s %s" % (name, value))

def get_alias(name):
	ret = pykd.dbgCommand(".echo %s"%(name)).strip()
	pykd.dbgCommand(".echo") # clear last command
	if ret == name:
		return ''
	else:
		return ret

class Pig():
	def __init__(self):
		self.name = "cdb_pig"

	def logo(self):
		logo_color = ['lightmagenta','lightblue','lightred','green','yellow']
		auth_color = ['darkgray','brown','blue','cyan','red']
		try:
			wprint(logos[random.randint(0, len(logos) - 1)].decode("base64"), logo_color[random.randint(0, len(logo_color) - 1)])
			wprint(('mutepig-%s'%VERSION).rjust(random.randint(10, len(logos) + 10)), auth_color[random.randint(0, len(auth_color) - 1)])
			print('')
		except:
			wprint(('CDB-PIG mutepig-%s'%VERSION).rjust(random.randint(10, 50)), 'red')
			print('')

	def add_pig_cmd(self):
		pcmd = pigcmd()
		for cmd in pcmd.commands:
			if cmd not in ["run"]:
				set_alias(cmd, "!py %s %s" % (FILEPATH, cmd))

	def load_init(self):
		init_file = os.path.dirname(FILEPATH) + "\cdbinit"
		try:
			cdbinit = open(init_file).readlines()
		except:
			cdbinit = []

		for cmd in cdbinit:
			cmd = cmd.strip()
			try:
				pykd.dbgCommand(cmd)
				print(cmd)
			except:
				pass

	def run(self):
		try:
			args = []
			self.logo()
			self.add_pig_cmd()
			self.load_init()
			self.debugger = WinDbgAdaptor(*args)
			self.command = WinDbgCommand(*args)
		except Exception as e:
			print(e)

class pigcmd():
	def __init__(self):
		self.commands = [c for c in dir(self) if callable(getattr(self, c)) and not c.startswith("_")] 
		if len(sys.argv)>1:
			self.func = sys.argv[1]
		if len(sys.argv)>2:
			self.args = sys.argv[2:]
		else:
			self.args = []
		if "!py" in self.args:
			self.args.remove("!py")
		if FILEPATH in self.args:
			self.args.remove(FILEPATH)

	def _error_args(self):
		print(getattr(self, self.func).__doc__)

	def run(self):
		if self.func in self.commands:
			#try:
			getattr(self, self.func)(*self.args) 
			#except:
			#	self._error_args()
		else:
			error_msg("pigcmd error")

	def help(self, command=None):
		"""
		Get the help of command.
		"""
		if command:
			print(getattr(self, command).__doc__)
		else:
			for cmd in self.commands:
				if cmd not in ["run"]:
					wprint(cmd.ljust(10), "lightred")
					print(getattr(self, cmd).__doc__.strip().splitlines()[0])

	def test(self, tname1="RedBoy", tname2="KeGua"):
		"""
		Test for command and args.
		Args:
			- tname1(string): test name 1 
			- tname2(string): test name 2
		"""
		wprint("Mutepig say hello to %s and %s!" % (tname1, tname2), "lightred")
		print("")

	def watch(self, dc, addr='', num=16):
		"""
		Run command every step.
		Args:
			- display_command(string): eg. dd,dw .   or you can disable it by input 'clear'
			- addr (hex): the address to be watch.
			- num (int) : the number of line to be watch. (optional)
		"""
		if dc=='clear':
			pykd.dbgCommand("ad watch_command")
		else:
			set_alias("watch_command", "%s %s %s"%(dc, addr, num))

	def ct(self, type='', addr='', count=10):
		"""
		Run context().
		Args:
			- context type(char): r, d, s
			- address(hex): if you choose disassemble, you can input address where you want to see. (optional)
			- count(int): the number of instructions to disassemble. (optional)
		"""
		debugger = WinDbgAdaptor()
		if not type:
			debugger.context()
		elif type == 'r':
			debugger.context_register()
		elif type == 's':
			debugger.context_stack()
		elif type == 'd':
			try:
				if not addr:
					debugger.context_code()
				elif not count:
					addr = to_int(addr)
					text = debugger.disassemble_around(addr)
					cprint(format_disasm_code(text, addr))
				else:
					addr = to_int(addr)
					count = int(count)
					text = debugger.disassemble_around(addr, count)
					cprint(format_disasm_code(text, addr))
			except Exception as e:
				print(e)
				self._error_args()
		else:
			self._error_args()

	def grep(self, command, regex_string, a='', b=''):
		"""
		Grep regex_string in the result of command
		Args:
			- command(string)
			- regex_string (string)
			- after_context(int) (optional)
			- before_context(int) (optional)
		"""
		try:
			a = to_int(a)
			b = to_int(b)
		except:
			return self._error_args()

		result = pykd.dbgCommand(command)
		lines = result.splitlines()
		for idx,line in enumerate(lines):
			if regex_string in line:
				print("="*50)
				print('\n'.join(lines[idx-a:idx]))
				wprint(lines[idx]+"\n", "lightred")
				print('\n'.join(lines[idx+1:idx+b+1]))

	def memory(self, addr, count=10):
		"""
		Get the data chain in memory.
		Args:
			- address(hex)
			- count(int)
		"""
		debugger = WinDbgAdaptor()
		debugger.telescope(to_int(addr), int(count))

	def dis(self, addr1, addr2):
		"""
		Get the distance of addr1 and addr2.
		Args:
			- address1(hex)
			- address2(hex)
		"""
		print("%s - %s = 0x%x"%(addr2, addr1, to_int(addr2)-to_int(addr1)))

	def reload(self):
		"""
		Reload CDB-PIG.
		"""
		print("!py --global %s"%FILEPATH)

	def _open_init(self, type='r'):
		init_file = os.path.dirname(FILEPATH) + "\cdbinit"
		try:
			cdbinit = open(init_file, type)
			return cdbinit
		except:
			error_msg("CDBINIT is not access!")
			return None

	def _get_init(self):
		f = self._open_init()
		content = f.readlines()
		f.close()
		ret = []
		for line in content:
			if line.strip():
				ret.append(line)
		return ret

	def cdbinit(self, opt='', arg=''):
		"""
		add/edit/delete command in cdbinit.
		Args:
			- option(char): l(list), a(add), e(enable), d(disable), c(delete) 
			- command(string)/linenumber(int): add command/enable or disable or delete command in the number of line
		"""
		if not opt or opt=='l':
			content = self._get_init()
			for idx,line in enumerate(content):
				if line.startswith('#'):
					wprint("%d   [d]%s"%(idx, line.strip()[1:]), "lightred")
				else:
					wprint("%d   [e]%s"%(idx, line.strip()), "green")
				print("")
		elif opt == 'a' and arg:
			f = self._open_init('a+')
			try:
				last = f.readlines()[-1]
				if not last.endswith("\n"):
					f.write("\n")
			except:
				pass
			f.write(arg + '\n')
			f.close()
		elif opt in ['e','d','c'] and arg:
			content = self._get_init()
			f = self._open_init('w')
			if arg!='*':
				try:
					linenumber = int(arg)
				except:
					return self._error_args()

			result = ""
			for idx,line in enumerate(content):
				if arg=='*' or idx == linenumber:
					if opt == 'e' and line.startswith('#'):
						result += line[1:]
					elif opt == 'd' and not line.startswith('#'):
						result += '#'+line
					elif opt == 'c':
						continue
					else:
						result += line
				else:
					result += line
			f.write(result)
			f.close()

	def update(self):
		"""
		Update cdb-pig from github.
		"""
		try:
			import urllib
		except:
			error_msg("you should install `urllib` first!")
		git_url = "https://raw.githubusercontent.com/mutepigz/cdb-pig/master/cdbpig"
		for i in ['/pig.py', '/lib/color.py', '/lib/utils.py']:
			try:
				urllib.urlretrieve(git_url+i, os.path.dirname(FILEPATH)+i.replace("/","\\"))
				success_msg("UPDATE %s" % i)
			except:
				error_msg("UPDATE %s" % i)



if __name__ == '__main__':
	pig = Pig()
	if len(sys.argv)>1:
		pigcmd = pigcmd()
		pigcmd.run()
	else:
		pig.run()
