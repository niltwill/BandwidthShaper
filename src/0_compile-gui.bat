@echo off
setlocal

:: Detect VS version (TODO: add /wd5105 for VS 2019)
set VS_VER=0

:: Files to compile
set FILES=gui_main.c gui_utils.c gui_proc_list.c gui_dialogs.c args_parser.c shaper_core.c shaper_utils.c schedule.c token_bucket.c pid_cache.c

:: Linker settings
set LINKER=ws2_32.lib Advapi32.lib Kernel32.lib User32.lib iphlpapi.lib gdi32.lib shell32.lib comctl32.lib comdlg32.lib ole32.lib version.lib uxtheme.lib

:: WinDivert libs
set WINDIVERT_X86=external\lib\X86\WinDivert.lib
set WINDIVERT_X64=external\lib\X64\WinDivert64.lib
set WINDIVERT_ARM64=external\lib\ARM64\WinDivert.lib

:: Release paths
set REL_X86=release\GUI\x86\BandwidthShaper.exe
set REL_X64=release\GUI\x64\BandwidthShaper.exe
set REL_ARM64=release\GUI\arm64\BandwidthShaper.exe

:: --------------------------------
:: GUI
:: --------------------------------

:: x86
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" (
    set VS_VER=2022
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat" (
    set VS_VER=2019
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
)

if not defined VSINSTALLDIR (
    echo ERROR: Visual Studio not found.
    pause & exit /b 1
)

rc /fo resource.res resource.rc
if %ERRORLEVEL% neq 0 (
    echo ERROR: rc.exe failed. Fix resource.rc before linking.
    pause & exit /b %ERRORLEVEL%
)

cl /EHsc /std:c17 /TC ^
    /DUNICODE /D_UNICODE %FILES% ^
    /link /out:%REL_X86% ^
    %WINDIVERT_X86% %LINKER% ^
    resource.res
if %ERRORLEVEL% neq 0 (
    echo ERROR: Compilation failed.
    pause & exit /b %ERRORLEVEL%
)

:: x64
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set VS_VER=2022
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set VS_VER=2019
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" >nul
)

if not defined VSINSTALLDIR (
    echo ERROR: Visual Studio not found.
    pause & exit /b 1
)

rc /fo resource.res resource.rc
if %ERRORLEVEL% neq 0 (
    echo ERROR: rc.exe failed. Fix resource.rc before linking.
    pause & exit /b %ERRORLEVEL%
)

cl /EHsc /std:c17 /TC ^
    /DUNICODE /D_UNICODE %FILES% ^
    /link /out:%REL_X64% ^
    %WINDIVERT_X64% %LINKER% ^
    resource.res
if %ERRORLEVEL% neq 0 (
    echo ERROR: Compilation failed.
    pause & exit /b %ERRORLEVEL%
)

:: ARM64
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set VS_VER=2022
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" amd64_arm64
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set VS_VER=2019
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" amd64_arm64
)

if not defined VSINSTALLDIR (
    echo ERROR: Visual Studio not found.
    pause & exit /b 1
)

rc /fo resource.res resource.rc
if %ERRORLEVEL% neq 0 (
    echo ERROR: rc.exe failed. Fix resource.rc before linking.
    pause & exit /b %ERRORLEVEL%
)

cl /EHsc /std:c17 /TC ^
    /DUNICODE /D_UNICODE %FILES% ^
    /link /out:%REL_ARM64% ^
    %WINDIVERT_ARM64% %LINKER% ^
    resource.res
if %ERRORLEVEL% neq 0 (
    echo ERROR: Compilation failed.
    pause & exit /b %ERRORLEVEL%
)
