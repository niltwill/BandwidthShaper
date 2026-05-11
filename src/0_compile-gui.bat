@echo off
setlocal
call :setvars

:: --------------------------------
:: GUI
:: --------------------------------

:: Pre-generate the language file
python localization_generate.py
if %ERRORLEVEL% neq 0 (
    echo ERROR: Failed to generate localization_data.c
    pause & exit /b %ERRORLEVEL%
)

:: X86
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VS_INSTALL=%%i
if not defined VS_INSTALL ( echo ERROR: Visual Studio not found. & pause & exit /b 1 )
call "%VS_INSTALL%\VC\Auxiliary\Build\vcvars32.bat"

rc /fo resource.res resource.rc
if %ERRORLEVEL% neq 0 (
    echo ERROR: rc.exe failed. Fix resource.rc before linking.
    pause & exit /b %ERRORLEVEL%
)

cl /EHsc /std:c17 /TC ^
    %COMPILE_FLAGS% ^
    %FILES% ^
    /link /out:%REL_X86% ^
    %WINDIVERT_X86% %LINKER% ^
    resource.res
if %ERRORLEVEL% neq 0 (
    echo ERROR: Compilation failed.
    pause & exit /b %ERRORLEVEL%
)

:: Reset PATH for next arch
endlocal & setlocal
call :setvars

:: X64
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VS_INSTALL=%%i
if not defined VS_INSTALL ( echo ERROR: Visual Studio not found. & pause & exit /b 1 )
call "%VS_INSTALL%\VC\Auxiliary\Build\vcvars64.bat" >nul

rc /fo resource.res resource.rc
if %ERRORLEVEL% neq 0 (
    echo ERROR: rc.exe failed. Fix resource.rc before linking.
    pause & exit /b %ERRORLEVEL%
)

cl /EHsc /std:c17 /TC ^
    %COMPILE_FLAGS% ^
    %FILES% ^
    /link /out:%REL_X64% ^
    %WINDIVERT_X64% %LINKER% ^
    resource.res
if %ERRORLEVEL% neq 0 (
    echo ERROR: Compilation failed.
    pause & exit /b %ERRORLEVEL%
)

:: Reset PATH for next arch
endlocal & setlocal
call :setvars

:: ARM64
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set VS_INSTALL=%%i
if not defined VS_INSTALL ( echo ERROR: Visual Studio not found. & pause & exit /b 1 )
call "%VS_INSTALL%\VC\Auxiliary\Build\vcvarsall.bat" amd64_arm64

rc /fo resource.res resource.rc
if %ERRORLEVEL% neq 0 (
    echo ERROR: rc.exe failed. Fix resource.rc before linking.
    pause & exit /b %ERRORLEVEL%
)

cl /EHsc /std:c17 /TC ^
    %COMPILE_FLAGS% ^
    %FILES% ^
    /link /out:%REL_ARM64% ^
    %WINDIVERT_ARM64% %LINKER% ^
    resource.res
if %ERRORLEVEL% neq 0 (
    echo ERROR: Compilation failed.
    pause & exit /b %ERRORLEVEL%
)

:setvars
:: Files to compile
set FILES=localization_api.c localization_data.c gui_main.c gui_utils.c gui_proc_list.c gui_dialogs.c args_parser.c shaper_core.c shaper_utils.c schedule.c token_bucket.c pid_cache.c

:: Linker settings
set LINKER=ws2_32.lib Advapi32.lib Kernel32.lib User32.lib iphlpapi.lib gdi32.lib shell32.lib comctl32.lib comdlg32.lib ole32.lib version.lib uxtheme.lib

:: Compile flags
set COMPILE_FLAGS=-DCLI_APP_BUILD=0 -DUNICODE /D_UNICODE /utf-8

:: WinDivert libs
set WINDIVERT_X86=external\lib\X86\WinDivert.lib
set WINDIVERT_X64=external\lib\X64\WinDivert64.lib
set WINDIVERT_ARM64=external\lib\ARM64\WinDivert.lib

:: Release paths
set REL_X86=release\GUI\x86\BandwidthShaper.exe
set REL_X64=release\GUI\x64\BandwidthShaper.exe
set REL_ARM64=release\GUI\arm64\BandwidthShaper.exe
goto :eof
