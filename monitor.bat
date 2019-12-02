@ECHO OFF
TITLE Client Monitor
COLOR 0A

SET LOGFILE="C:\yourLogFileLocation"
SET CLIMONAPP="C:\pathto\Client-Monitor.ps1"
SET CLIENTSLIST="C:\if_using\define_here\clients.txt"

REM Code to be run BEFORE the monitor runs...

REM ...


ECHO Running Client Monitor...
REM Don't forget that you can add more manual parameters to this call.
>%LOGFILE% powershell.exe -File "%CLIMONAPP%" -ClientsList "%CLIENTSLIST%"


REM Code to be run AFTER the monitor runs...

REM ...