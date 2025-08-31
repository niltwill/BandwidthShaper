@echo off

:: Enable delayed variable expansion
setlocal enabledelayedexpansion

pushd "%CD%"
CD /D "%~dp0"

:: Define the file where the parameters are stored
set PARAMS_FILE=params.txt

:: Check if the parameters file exists
if not exist "%PARAMS_FILE%" (
    echo Parameters file not found: %PARAMS_FILE%
    pause
    exit /b
)

:: Initialize the FLAGS variable
set FLAGS=

:: Read parameters from the file and append them to the FLAGS variable
for /f "delims=" %%A in (%PARAMS_FILE%) do (
    :: Skip lines that are empty or are comments (starting with "::", ";", or "#")
    set line=%%A
    if not "!line!"=="" if "!line:~0,2!" neq "::" if "!line:~0,1!" neq ";" if "!line:~0,1!" neq "#" (
        :: If FLAGS is not empty, add a space before appending
        if defined FLAGS (
            set FLAGS=!FLAGS! %%A
        ) else (
            set FLAGS=%%A
        )
    )
)

:: Check architecture (x86 or x64)
if "%PROCESSOR_ARCHITECTURE%"=="x86" (
    set RUN=x86\BandwidthShaper.exe
) else if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set RUN=x64\BandwidthShaper.exe
) else if "%PROCESSOR_ARCHITECTURE%"=="ARM64" (
    set RUN=arm64\BandwidthShaper.exe
) else (
    echo Unknown architecture.
    pause
    exit /b
)

:: Make sure the executable file exists
if not exist "%RUN%" (
    echo "%RUN%" does not exist.
    pause
    exit /b
)

:: Combine RUN and FLAGS
set COMBINED=%RUN% !FLAGS!

:: Display the final command
echo Executing: %COMBINED%

:: Execute the command
%COMBINED%

:: Pause to keep the window open after execution
pause
