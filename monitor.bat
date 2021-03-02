@ECHO OFF
TITLE Client Monitor
COLOR 0A

SET LOGFILE="C:\youorLogFileLocation\cli-mon-%date:/=-%--%time::=-%.log"
SET CLIMONAPP="C:\pathToCliMon\Client-Monitor.ps1"
REM SET CLIENTSLIST="C:\if_using\define_here\clients.txt"

REM Code to be run BEFORE the monitor runs...

REM ...


ECHO Running Client Monitor...
REM Don't forget that you can add more manual parameters to this call.
REM >%LOGFILE% powershell.exe -File "%CLIMONAPP%" -ClientsList "%CLIENTSLIST%"
>%LOGFILE% powershell.exe -File "%CLIMONAPP%"


REM Code to be run AFTER the monitor runs...

REM ...