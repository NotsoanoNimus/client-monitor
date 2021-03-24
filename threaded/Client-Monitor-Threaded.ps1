# Client-Monitor-Threaded.ps1
#
#

######################################################################################
# Copyright (C) 2019 @NotsoanoNimus on GitHub, as a free software project
#  licensed under GNU GPLv3.
#
# Original Repository: https://github.com/NotsoanoNimus/client-monitor
# Author: Notsoano Nimus <github@xmit.xyz>
#
# This program is free software: you can redistribute it and/or modify it under
#  the terms of the GNU General Public License as published by the Free Software
#  Foundation, either version 3 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
#  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
#  FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
#  this program. If not, see https://www.gnu.org/licenses/.
######################################################################################


# Gather parameters called with the application, and set the initial state as needed.
param(
    [int]$Debug = 0,
    [String]$ClientsList = "use-AD-list",
    [Switch]$DeltasReport = $False,
    [Switch]$NoNotifications = $False,
    [String]$BCC = "",
    [Switch]$NoMini = $False,
    [String]$DomainUserFilter = "",
    [Switch]$SnapshotMode = $False,
    [Switch]$NoFilters = $False,
    [Switch]$AsAttachment = $False,
    [Switch]$FlatReportCsv = $False,
    [Switch]$Ephemeral = $False,
    [String]$ConfigFile = "$(Split-Path $PSCommandPath)\..\Client-MonitorConfig.ps1",
    [PSCredential]$SmtpCredential = $null,
    [Swtich]$DevMode = $False
)
# Immediately clear all errors.
$Error.Clear()
# Start with a few basic parameter checks and static values based on the paramters.
$CompressJSON = (-Not $NoMini)
# Ensure that the ConfigFile exists.
if(-Not(Test-Path "$($ConfigFile)")) {
    Write-Error "The specified configuration file `"$ConfigFile`" does not exist."
    exit 1
} elseif (-Not(Test-Path "$(Split-Path $PSCommandPath)\..\lib\imports.ps1")) {
    Write-Error "The 'lib/' directory for Client-Monitor dependencies must be available to the script!"
    exit 2
}


##################################################
#                    SOURCING                    #
##################################################
# Set up whether or not the dev profile will be used. See Client-MonitorConfig.ps1 for more.
$global:DevProfileEnabled = $DevMode

# Import all relevant Client-Monitor objects, methods, and global definitions.
# Start by getting the directory that the script is currently executing from (to ease imports).
$CliMonScriptDirectory = Split-Path $PSCommandPath

# Global configuration variables are sourced from a separate file
#  (either specified, or in the same directory as the script).
. "$($ConfigFile)"

# The 'lib/' directory is essential to the script, and the directory
#  must be in the same directory as the script.
try {
    # DEBUG: Remove/Comment this upon release. Refreshes the module each time the script runs.
    Remove-Module "CliMonClient" -ErrorAction SilentlyContinue
} catch {}
# Importing the "imports" file brings in all the necessary pieces of the Client Monitor script,
#  and also (importantly) sets the default state for all global-scope variables.
. "$CliMonScriptDirectory\lib\imports.ps1"

# Sanity check to ensure the provided config file is a valid client-monitor configuration.
if($global:CliMonConfig.ConfigImported -ne $True) {
    Write-Error ("The given configuration file `"$ConfigFile`" " +
        "is not a valid Client Monitor configuration.")
    exit 1
} elseif ($ImportedDependencies -ne $True) {
    Write-Error "Could not import the necessary dependencies for the script to run."
    exit 2
}


##################################################
#                      CORE                      #
##################################################
<#
Process for the "new" monitoring script:
- Create an empty manifest, time-based log object that holds all change information since the last notification.
--- ENUM ManifestRowType { ADD, REMOVE, CHANGE, ...??? };
--- CLASS ManifestEntry {
        $CliMonClient; $Timestamp ; $RowType ; $ObjectPrev ; $ObjectNew;
        static string 
    }
--- CLASS MANIFEST {
        $reportStream = @( ManifestEntry101, ManifestEntry102, ManifestEntry103, ..., ManifestEntry### );
        string GetAllTypeForHost(string $who, ManifestRowType $type) { return $this.$reportStream | ? {$_.RowType -eq $type -And $_.CliMonClient.Hostname -eq $who}; }
        string ToNotif() {...iterate $ReportStream...}
    }
- initialize all sessions possible at start
--- send an optional notification on start of deltas since the last run/check (recommended)
- enter a loop that listens for events/jobs in each PS-Session
--- thought process is to use either Start-Stop-Receive Job commands for each PSSession to "thread"
        connections and offload telemetry harvesting, or use some kind of custom event handling
--- Gather client information and record any changes locally; as they're recorded, pile them into the manifest
--- While listening, be sure to record any outages and re-assertions of sessions that had died
--- At every check interval, the current manifest (UUID to find current) should be recorded in full, in case the CliMon master host dies
- At the configured interval, send the monitor notification with all compiled manifest info.
--- Log the current manifest contents somewhere so CliMon knows it was sent
--- Clear the manifest and continue listening.
#>


# Keep track of all queued jobs for all clients.
$global:CliMonJobRoster = @()

# Processes to run on initialization and whenever the clients list needs to be refreshed.
#  Reasserts dead sessions, any clients that never connected in the first place, 
Function Assert-ClientSessions() {
    # Get target clients

    # Check for sessions that may already be open

    # Record and attempt to open any sessions for clients that aren't currently valid/open

    # For any new session, redefine all global variables and functions on the target machine
    #   Includes any data collection and reporting functions needed
}


Function Watch-Clients() {
    # Run data collection jobs for all remote sessions and collect the job information
    ####foreach($session in $global:clientSessions) { blah blah }

    # Wait AT LEAST the configured interval before doing anything else
    Start-Sleep -Seconds 300   #will be a config value later.

    # Wait on all jobs to come back as finished.
    #   If any job exceeds XXX seconds EXTRA time beyond the interval above, it will be forced to stop.
    $workingJobs = $global:CliMonJobRoster | Where-Object -Property State -eq "Running"
    if($null -ne $workingJobs -And $workingJobs.Count -gt 0) {
        $workingJobs | Wait-Job -Timeout 300   #will be a configurable forced timeout
    }

    # Catalog all received information into the running manifest.

    # Record state information about the current manifest, and track its UUID
    #   (so the program knows where to look in the event of an unexpected script crash/shutdown)

    # Check to see if it's time for another Assert-ClientSessions call

    # Check to see if it's time to build and send out a notification containing the currently-active manifest data.
}




# Initialize the application and put it in an endless monitoring loop.
try {
    Assert-ClientSessions
    while($true) { Watch-Clients }
} catch {
    # Could issue a service crash notification, if configured
} finally {

}