@echo off
set PYTHON_PATH=C:\Python27
set WINDBG_PATH=C:\Program Files\Debugging Tools for Windows (x86)

if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
	set BITS=64
) else (
	set BITS=32
)

echo start setup
echo upgrade pip ...
pip install pip-10.0.1-py2.py3-none-any.whl
echo install dependence
pip install six-1.11.0-py2.py3-none-any.whl
echo setup pykd

if %BITS%==64 (
	pip install pykd-0.3.3.4-cp27-none-win_amd64.whl
	copy "PYKD_BOOTSTRAPPER_2.0.0.16\x64\pykd.dll" "%WINDBG_PATH%\"
) else (
	pip install pykd-0.3.3.4-cp27-none-win32.whl
	copy "PYKD_BOOTSTRAPPER_2.0.0.16\x86\pykd.dll" "%WINDBG_PATH%\"
)
copy "%PYTHON_PATH%\Lib\site-packages\pykd\pykd.pyd" "%WINDBG_PATH%\winext"
echo move cdbpig
xcopy "cdbpig" "%PYTHON_PATH%\Lib\site-packages\cdbpig\" /e /s /y
echo init cdbpig
echo cdb -c ".load pykd; !py --global %PYTHON_PATH%\Lib\site-packages\cdbpig\pig.py" %%* > "%WINDBG_PATH%\cdbpig.bat"
echo success!
