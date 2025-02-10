@echo off

:: x86
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
rc /fo resource.res resource.rc
cl /EHsc /std:c17 /Fe:BandwidthShaper32.exe /wd5105 BandwidthShaper.c WinDivert.lib ws2_32.lib Advapi32.lib Kernel32.lib resource.res

:: x64
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
rc /fo resource.res resource.rc
cl /EHsc /std:c17 /Fe:BandwidthShaper64.exe /wd5105 BandwidthShaper.c WinDivert64.lib ws2_32.lib Advapi32.lib Kernel32.lib resource.res

:: Pause to keep the window open after execution
pause