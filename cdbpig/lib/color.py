import sys
import re
import os
try:
	from ctypes import *
except:
	print 'I need module ctypes'
	sys.exit()

# command colors
cc_map = {
	'default'	  :0,
	'black'		:1,
	'blue'		 :2,
	'green'		:3,
	'cyan'		 :4,
	'red'		  :5,
	'magenta'	  :6,
	'brown'		:7,
	'lightgray'	:8,
	'darkgray'	 :9,
	'lightblue'	:10,
	'lightgreen'   :11,
	'lightcyan'	:12,
	'lightred'	 :13,
	'lightmagenta' :14,
	'yellow'	   :15,
	'white'		:16,
};

ll_map = {
	30 : 'black',
	31 : 'lightred',
	32 : 'lightgreen',
	33 : 'yellow',
	34 : 'lightblue',
	35 : 'red',
	36 : 'cyan',
	37 : 'white',
	86 : 'brown',
	87 : 'lightcyan',
	88 : 'lightmagenta',
	89 : 'magenta',
	90 : 'darkgray',
}
CloseHandle = windll.kernel32.CloseHandle
GetStdHandle = windll.kernel32.GetStdHandle
GetConsoleScreenBufferInfo = windll.kernel32.GetConsoleScreenBufferInfo
SetConsoleTextAttribute = windll.kernel32.SetConsoleTextAttribute
#www.iplaypy.com
 
STD_OUTPUT_HANDLE = -11
 
class COORD(Structure):
   _fields_ = [('X', c_short),
			   ('Y', c_short),
			  ]
 
class SMALL_RECT(Structure):
   _fields_ = [('Left', c_short),
			   ('Top', c_short),
			   ('Right', c_short),
			   ('Bottom', c_short),
			  ]
				
class CONSOLE_SCREEN_BUFFER_INFO(Structure):
   _fields_ = [('dwSize', COORD),
			   ('dwCursorPosition', COORD),
			   ('wAttributes', c_uint),
			   ('srWindow', SMALL_RECT),
			   ('dwMaximumWindowSize', COORD),
			  ]
 
def wprint(text, fore_color='white', back_color='black',y=0):
	if not (cc_map.has_key(fore_color) and
			cc_map.has_key(back_color)):
		print fore_color, back_color, " are invalid color strings"
		return
 
	#prepare
	hconsole = GetStdHandle(STD_OUTPUT_HANDLE)
	cmd_info = CONSOLE_SCREEN_BUFFER_INFO()
	GetConsoleScreenBufferInfo(hconsole, byref(cmd_info))
	old_color = cmd_info.wAttributes

	#calculate colors
	fore = cc_map[fore_color]
	if fore: fore = fore - 1
	else: fore = old_color & 0x0F
	back = cc_map[back_color]
	if back: back = (back - 1) << 4
	else: back = old_color & 0xF0

	#real output
	SetConsoleTextAttribute(hconsole, fore + back)
	if y:
		print(text)
	else:
		sys.stdout.write(text) 
		sys.stdout.flush()
	SetConsoleTextAttribute(hconsole, old_color)

'''
def cprint(text):
	i = 0
	text = text.strip()
	pattern = re.compile("\033\[;(\d)?;(\d\d)?m(.*?)\033\[0m")
	matches = pattern.findall(text)
	for (st, fc, str) in matches:
		if i<text.find(cc,i):
			print(text[i: text.find(cc,i)]),
		(fc,str) = re.findall("\033\[;(\d\d)m(.*?)\033\[0m",cc)[0]
		fc = ll_map[int(fc)]
		wprint(str, fc)
		i = text.find(cc,i) + len(cc)
	print text[i:]
'''
def cprint(text):
	i = 0
	next_format = text.find("\033[;", i)
	while i < len(text):
		if next_format < 0:
			wprint(text[i:])
			break
		wprint(text[i:next_format])
		i = next_format
		next_format = text.find("\033[;", i+1)
		pattern = re.compile("\033\[;(\d;)?(\d\d)?m(.*?)\033\[0m")
		if next_format < 0:
			(st, fc, str) = pattern.findall(text[i:])[0]
		else:
			(st, fc, str) = pattern.findall(text[i:next_format])[0]
		if st:
			st = int(st[:-1])
		else:
			st = "black"
		if st == 1:
			st = "cyan"
		elif st==2:
			fc = 90
			st = "black"
		fc = ll_map[int(fc)]
		i = text.find("\033[0m",i)+4
		wprint(str,fc,st)

def debug(text):
	wprint("[DEBUG] ","red")
	print(text)

if __name__ == "__main__":
	print("  Color map:")
	keys = [key for key in cc_map]
	for i in range(11, -1, -1): #12 is the max len, "lightmagenta"
		print " " * 20,
 
		for j in range(0, 17):
			k = keys[j]
			l = len(k)
			c = ' '
			if l > i:
				c = k[l - i - 1]
			print(" %s" % c),
		print
	#lines with color and background cresponding to i & j
	for fc in keys:
			print "		%12s " % fc, 
			for bc in keys:
				wprint(":)",fc, bc)
			print