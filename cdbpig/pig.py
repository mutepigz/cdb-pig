# -*- coding: utf-8 -*-
import pykd
import os
import sys
import pykd
import re
import string
import random
from time import time

VERSION = "0.2"
FILEPATH = os.path.abspath(sys.argv[0])
while os.path.islink(FILEPATH):
	FILEPATH = os.readlink(FILEPATH)
sys.path.insert(0, os.path.dirname(FILEPATH))
sys.path.insert(0, os.path.dirname(FILEPATH) + "/lib/")

from logo import logos
from color import cprint,wprint,debug
from utils import *

class DebuggerCommand(pykd.eventHandler):
	"""
	The `voltron` command in the debugger.
	"""
	def __init__(self):
		pykd.eventHandler.__init__(self)
		self.adaptor = DebuggerAdaptor()

	def onExecutionStatusChange(self, status):
		if status == pykd.executionStatus.Break: # step, trace, ...
			self.adaptor.update_state()

class DebuggerAdaptor(object):
	reg_names = {
		"x86":	  {"pc": "eip", "sp": "esp"},
		"x86_64":   {"pc": "rip", "sp": "rsp"},
	}
	REGISTERS = {
	8 : ["al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"],
	16: ["ax", "bx", "cx", "dx"],
	32: ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"],
	64: ["rax", "rbx", "rcx", "rdx", "rsi", "rdi","r8", "r9", "r10",
		 "r11", "r12", "r13", "r14", "r15","rbp", "rsp", "rip",]
	}

	def __init__(self, *args, **kwargs):
		self.listeners = []
		self.command = WinDbgCommand()

	def update_state(self):
		self.context()
		pykd.breakin()
		#self.watch()


	def pc(self, target_id=0, thread_id=None):
		return self.program_counter(target_id, thread_id)

	def sp(self, target_id=0, thread_id=None):
		return self.stack_pointer(target_id, thread_id)

	sizes = {
		'x86': 4,
		'x86_64': 8,
	}
	max_deref = 24
	max_string = 128
	def __init__(self, *args, **kwargs):
		self.listeners = []
		self.host = pykd
		self.watch_command = ""

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


	def state(self, target_id=0):
		"""
		Get the state of a given target.
		"""
		return self._state()

	def watch(self):
		"""
		Show the memory by watch_command.
		"""
		self.watch_command = get_alias("watch_command")
		if watch_command:
			wprint("[%s]" % "memory".center(200, "-"),"lightblue")
			print("")
			if 'last_watch' not in dir(self):
				self.last_watch = ''
			(dc, addr, num) = watch_command.strip().split()
			if dc not in ['db','dd','dq','dp','dw']:
				error_msg("%s is not supported!"%dc)
				return []
			now_watch = self.dumpmem(to_int(addr), int(num), dc)
			self.watch_show(to_int(addr), now_watch, self.last_watch, dc[1])
			self.last_watch = now_watch

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

	def watch_show(self, base_addr, now, last='', c='', count=0x8):
		line = 0
		n = 0
		if not c or c =='p':
			step = self._target()['addr_size']<<1
		else: 
			step = 2<<['b','w','d','q'].index(c)
		for idx,n in enumerate(now):
			if idx%count == 0 :
				print("")
				wprint(to_hex(base_addr+line*count)+"  ","cyan")
			if idx<len(last) and last[idx]!=n:
				wprint(just_hex(n, step), "lightred")
			else:
				wprint(just_hex(n, step))
			wprint(" ")
			line+=1
		print("")

	def get_reg(self, regname=''):
		if not regname:
			return self.registers()
		return pykd.reg(regname)



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

	@memoized
	def is_executable(self, address):
		if pykd.isKernelDebugging():
			return False
		if "Execute" in str(pykd.getVaProtect(address)):
			return True
		else:
			return False

	@memoized
	def is_writable(self, address):
		if pykd.isKernelDebugging():
			return False
		if "Write" in str(pykd.getVaProtect(address)):
			return True
		else:
			return False

	@memoized
	def is_address(self, value):
		if is_int(value):
			return pykd.isValid(value)
		else:
			return False

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
		if self.is_executable(address):
			func = pykd.findSymbol(address)
			disasm = pykd.disasm(address).instruction().split(" ",2)[-1].strip()
			return (func, disasm)
		else:
			return (None, None)

	@memoized
	def examine_mem_reference(self, value, depth=5	):
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
			result += [(v, t, to_hex(vn))]

		while vn:
			if len(result) > depth:
				_v, _t, _vn = result[-1]
				result[-1] = (_v, _t, "--> ...")
				break

			result += [(v, t, to_hex(vn))]

			if is_str(vn):
				break
			if to_int(v) == vn or not self.is_address(vn): # point to self
				break
			if vn in [v for (v, _, _) in result]: # point back to previous value
				result[-1] = (v,t,to_hex(vn)+"(head)")
				break
			(v, t, vn) = self.examine_mem_value(vn)
		return result

	@memoized
	def examine_mem_value(self, value):
		"""
		Examine a value in memory for its type and reference

		Args:
			- value: value to examine (Int)

		Returns:
			- tuple of (value(Int), type(String), next_value(Int or String))
		"""
		def examine_data(value, step=4):
			try:
				out = pykd.loadQWords(value,1)[0] if step==8 else pykd.loadDWords(value,1)[0]
				if self.is_address(out):
					return out
			except:
				return value
			str = pykd.loadCStr(value)
			#str = pykd.loadWStr(value)
			if is_printable(str):
				if len(str)<step:
					return "%x \"%s\"" % (out, str)
				return str
			return out 

		if value is None:
			return [0, '', '']

		if not self.is_address(value): # a value
			result = (to_hex(value), "value", "")
			return result

		step = self._target()['addr_size']
		# check for writable first so rwxp mem will be treated as data
		if self.is_writable(value): # writable data address
			out = examine_data(value, step)
			result = (to_hex(value), "data", out)

		elif self.is_executable(value): # code/rodata address
			(func,disasm) = self.get_disasm(value)
			if func and disasm:
				result = (to_hex(value), "code", "(%s : %s)" % (yellow(func),purple(disasm)))
			else:
				out = examine_data(value, step)
				result = (to_hex(value), "data", out)

		else: # readonly data address
			out = examine_data(value, step)
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

	def dumpmem(self, start, count=0, step=''):
		result = []
		step = self._target()['addr_size']

		if not dc:
			dc = "d%s" % ("q" if step == 8 else "d")
		if count is not None:
			try:
				ret = pykd.loadQWords(value,count) if step==8 else pykd.loadDWords(value,count)
			except:
				error_msg("dump memory failed")
				return ""

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
		result = []
		for offset in xrange(-count,0):
			addr = pykd.disasm().findOffset(offset)
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

		# check if address is reachable

		if pc is None or not self.is_address(pc) or not self.is_executable(pc):
			error_msg("%x not access or executable!"%address)
			return None

		if prev:
			prev_code = self.prev_inst(pc, count//2)
		else:
			prev_code = []

		now_code = []
		for offset in xrange(0, count//2+1):
			addr = pykd.disasm(pc).findOffset(offset)
			comment = ""
			if pc == addr:
				if jump==1:
					comment = "JUMP is taken"
				elif jump==-1:
					comment = "JUMP is NOT taken"
			(func, code) = self.get_disasm(addr)
			if not func or not code:
				continue
			now_code += [(addr, code, func, comment)]
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
		next_addr = re.findall("\([0-9a-f`]*\)", inst)[0][1:-1]
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



	def context(self,target_id=0):
		wprint("[%s]" % "CDB-PIG".center(200, "-"),"lightred","black",1)
		self.context_register()
		self.context_code()
		self.context_stack()



	def context_register(self,target_id=0):
		wprint("[%s]" % "registers".center(200, "-"),"lightblue","black",1)
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

		wprint("[%s]" % "disassemble".center(200, "-"),"lightblue","black",1)
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



	def context_stack(self,count=10):
		wprint("[%s]" % "stack".center(200, "-"),"lightblue","black",1)
		text = ""
		nowsp = self.sp()[1]
		if self.is_address(nowsp):
			self.telescope(nowsp, count)
		else:
			wprint("Invalid $SP address: 0x%x"%nowsp, "lightred", "black", 1)
		return

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
			self.command = DebuggerCommand(*args)
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

	def _get_aim(self, aim):
		try:
			ret = to_int(aim)
		except:
			ret = 0
		if not ret:
			try:
				ret = pykd.reg(aim)
			except:
				ret = 0
		return ret

	def run(self):
		if self.func in self.commands:
			try:
				getattr(self, self.func)(*self.args) 
			except:
				self._error_args()
		else:
			error_msg("pigcmd error")

	def help(self, command=None):
		"""
		Get the help of command.
		"""
		if command:
			print(getattr(self, command).__doc__)
		else:
			print("Name".ljust(16)+"Description")
			print(("-"*10).ljust(16)+"-"*10)
			for cmd in self.commands:
				if cmd not in ["run"]:
					wprint(cmd.ljust(16), "lightred")
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

	def watch(self, dc, aim='', num=16):
		"""
		Run command every step.
		Args:
			- display_command(string): eg. dd,dw . Or you can disable it by inputing 'clear'
			- address(hex)/register(string): the address to be watch.
			- num (int) : the number of line to be watch. (optional)
		"""
		aim = self._get_aim(aim)
		if dc=='clear':
			pykd.dbgCommand("ad watch_command")
		else:
			if re.match("d[a-z]",dc):
				set_alias("watch_command", "%s %s %s"%(dc, to_hex(aim), num))
			else:
				return self._error_args()

	def ct(self, type='', aim='', count=10):
		"""
		Run context().
		Args:
			- context type(char): r, d, s
			- address(hex)/register(string): if you choose disassemble, you can input place where you want to see. (optional)
			- count(int): the number of instructions to disassemble. (optional)
		"""
		debugger = DebuggerAdaptor()
		if not type:
			debugger.context()
		elif type == 'r':
			debugger.context_register()
		elif type == 's':
			debugger.context_stack()
		elif type == 'd':
			try:
				if not aim:
					debugger.context_code()
				else:
					aim = self._get_aim(aim)
					text = debugger.disassemble_around(aim, int(count))
					cprint(format_disasm_code(text, aim))
			except:
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
				if a:
					print('\n'.join(lines[idx-a:idx]))
				wprint(lines[idx]+"\n", "lightred")
				if b:
					print('\n'.join(lines[idx+1:idx+b+1]))

	def memory(self, aim, count=10):
		"""
		Get data chain in memory.
		Args:
			- address(hex)/register(string)
			- count(int)
		"""
		aim = self._get_aim(aim)
		debugger = DebuggerAdaptor()
		debugger.telescope(aim, int(count))

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

	def search(self, aim, length, search, is_re=False):
		"""  
		Search for all instances of a pattern in memory from start to end
			 
		Args:
			- address(hex)/register(string): start address 
			- length(int): search length
			- search(string): hexstring(start with '0x') or string or python regex pattern 
			- re(int): use regex pattern or not
		"""
			 
		result = [] 
		start = self._get_aim(aim)
		length = to_int(length)
		end = start + length
		debugger = DebuggerAdaptor()
		mem = []
		for i in xrange(start, end, 0x10000):
			if i > end: i = end
			mem += debugger.dumpmem(i, min(0x10000, end-i), 'db')
		mem_str = ''.join([chr(i) for i in mem])
		print("Search from %x to %x" % (start, end))

		# unicode search string
		usearch = ''
		# hex search string
		hsearch = ''
		if not mem: 
			return result
			 
		if isinstance(search, six.string_types) and search.startswith("0x"):
			# hex number
			search = search[2:]
			if len(search) %2 != 0:
				search = "0" + search
			search = search.decode('hex')
			hsearch = search[::-1]
		elif not is_re:
			usearch = ''.join([(i+'\x00') for i in search])

		# Convert search to bytes if is not already
		if not isinstance(search, bytes):
			search = search.encode('utf-8')

		if not is_re:
			search = re.escape(search)
		try: 
			p = re.compile(search)
		except:
			search = re.escape(search)
		if usearch:
			search += "|" + usearch
		if hsearch:
			search += "|" + hsearch
		p = re.compile(search)

		found = list(p.finditer(mem_str))
		for m in found:
			index = 1
			if m.start() == m.end() and m.lastindex:
				index = m.lastindex+1
			for i in range(0,index):
				if m.start(i) != m.end(i):
					result += [(start + m.start(i), ''.join(["%02x"%i for i in mem[m.start(i):m.end(i)]]))]
		if not result:
			error_msg("Nothing Found!")
			return
		for i in result:
			(addr, hex) = i
			wprint("  %s "%to_hex(addr), "cyan")
			str = hex.decode("hex")
			if is_printable(str):
				print("%s(\"%s\")" % (hex, str))
			else:
				print(hex)


if __name__ == '__main__':
	pig = Pig()
	if len(sys.argv)>1:
		pigcmd = pigcmd()
		pigcmd.run()
	else:
		pig.run()
