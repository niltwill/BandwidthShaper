@echo off
:: For Visual Studio 2019 and 2022

setlocal

:: Detect VS version
set VS_VER=0

:: x86
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" (
    set VS_VER=2022
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat" (
    set VS_VER=2019
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
)

if defined VSINSTALLDIR (
    rc /fo resource.res resource.rc
    if "%VS_VER%"=="2019" (
        cl /EHsc /std:c17 /Fe:BandwidthShaper32.exe /wd5105 BandwidthShaper.c WinDivert.lib ws2_32.lib Advapi32.lib Kernel32.lib resource.res
    ) else (
        cl /EHsc /std:c17 /Fe:BandwidthShaper32.exe BandwidthShaper.c WinDivert.lib ws2_32.lib Advapi32.lib Kernel32.lib resource.res
    )
)

:: x64
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set VS_VER=2022
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set VS_VER=2019
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
)

if defined VSINSTALLDIR (
    rc /fo resource.res resource.rc
    if "%VS_VER%"=="2019" (
        cl /EHsc /std:c17 /Fe:BandwidthShaper.exe /wd5105 BandwidthShaper.c WinDivert64.lib ws2_32.lib Advapi32.lib Kernel32.lib resource.res
    ) else (
        cl /EHsc /std:c17 /Fe:BandwidthShaper.exe BandwidthShaper.c WinDivert64.lib ws2_32.lib Advapi32.lib Kernel32.lib resource.res
    )
)

:: ARM64
if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set VS_VER=2022
    call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" amd64_arm64
) else if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" (
    set VS_VER=2019
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" amd64_arm64
)

if defined VSINSTALLDIR (
    rc /fo resource.res resource.rc
    if "%VS_VER%"=="2019" (
        cl /EHsc /std:c17 /Fe:BandwidthShaper_ARM64.exe /wd5105 BandwidthShaper.c ARM64\WinDivert.lib ws2_32.lib Advapi32.lib Kernel32.lib resource.res
    ) else (
        cl /EHsc /std:c17 /Fe:BandwidthShaper_ARM64.exe BandwidthShaper.c ARM64\WinDivert.lib ws2_32.lib Advapi32.lib Kernel32.lib resource.res
    )
)

:: Pause to keep the window open after execution
pause
