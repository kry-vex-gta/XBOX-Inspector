@echo off
rem XBOX-Inspector launcher. Starts ONLY the inspector, with an explicit
rem working directory resolved from the unpack location (spaces/Cyrillic safe).
rem No administrator rights, no system changes.
setlocal
set "HERE=%~dp0"
start "" /D "%HERE%" "%HERE%bin\XBOX-Inspector.exe" gui
endlocal
