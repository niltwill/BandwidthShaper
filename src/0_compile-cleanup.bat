@echo off

:: CLI app
if exist "cli_main.obj" ( del /Q "cli_main.obj" )

:: GUI app
if exist "gui_dialogs.obj" ( del /Q "gui_dialogs.obj" )
if exist "gui_main.obj" ( del /Q "gui_main.obj" )
if exist "gui_proc_list.obj" ( del /Q "gui_proc_list.obj" )
if exist "gui_utils.obj" ( del /Q "gui_utils.obj" )

:: Common
if exist "args_parser.obj" ( del /Q "args_parser.obj" )
if exist "shaper_core.obj" ( del /Q "shaper_core.obj" )
if exist "shaper_utils.obj" ( del /Q "shaper_utils.obj" )
if exist "token_bucket.obj" ( del /Q "token_bucket.obj" )
if exist "pid_cache.obj" ( del /Q "pid_cache.obj" )
if exist "schedule.obj" ( del /Q "schedule.obj" )
if exist "resource.res" ( del /Q "resource.res" )
