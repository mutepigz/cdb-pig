# CDB-PIG
CDB-PIg is a plugin for cdb, but not windbg.

You can use it in CMD.

Thanks to project [voltron](https://github.com/snare/voltron), which help me to achieve `hook-stop`.

Thanks to project [peda](https://github.com/longld/peda).actually,CDB-PIG is peda in WINDOWS.

## KEY FEATURES:
* `registers`,`disassemble`,`stack` in every step
* use `cdbinit` to run command in the start of cdb
* you can customize your command in `pig.py`,please comply with the standard.Here is the demo code:
```
	def test(self, *args):
		"""
		Test for command and args.
		Args:
			- tname1: test name 1 (string)
			- tname2: test name 2 (string)
		"""
		try:
			(tname1, tname2) = args
		except:
			return self._error_args()

		wprint("Mutepig say hello to  %s and %s!" % (tname1, tname2), "lightred")
		print("")
```
* you can see memory every step, and when changed it will be highlight.
```
watch dX address number
```
* more command in `help`

## INSTALL
1. install windbg & python & pip in WINDOWS, and add them into envionment variables.
2. change `PYTHON_PATH` & `WINDBG_PATH` in `setup.bat`, then run it as Administrator. (if it doesn't work, install `pykd` by yourself)
3. run command and see if it works.
```
cdbpig
```

## SCREENSHOT
* jump or not
![](https://user-images.githubusercontent.com/16552633/41028742-a835267e-69ac-11e8-8357-c8323f70e1c3.png)
* call argument
![](https://user-images.githubusercontent.com/16552633/41028743-a88f8632-69ac-11e8-86fc-90d084a9680e.png)
* customize command
![](https://user-images.githubusercontent.com/16552633/41028738-a749c012-69ac-11e8-8edd-09e6f50d76a1.png)
* memory
![](https://user-images.githubusercontent.com/16552633/41028741-a7dc1584-69ac-11e8-81c7-846f0d791150.png)

## OTHER
if you have any question or suggestion, please contact with me!

enjoy it!
