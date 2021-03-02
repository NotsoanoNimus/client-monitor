<#
 # ClientSessions.ps1
 #
 # Get, start, and remove all Client Monitor sessions via session-manager methods.
 #  This script provides many of the critical startup and teardown functions.
 #>



######################################################################################
# Copyright (C) 2019 "Notsoano Nimus", as a free software project
#  licensed under GNU GPLv3.
#
# Original Repository: https://github.com/NotsoanoNimus/client-monitor
# Author: Notsoano Nimus <postmaster@thestraightpath.email>
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



# Called directly from the main function. This is another layer of wrapper functions for initial setup.
#  It serves to get and clean a list of CliMonClient objects according to MSAD or the ClientsList param.
Function Get-ClientSessions() {
    param([String][Parameter(Mandatory=$True)]$ClientsList)
    Write-Host "`n`n`nInstantiating client objects and running connectivity tests." `
        -ForegroundColor Green
    # Define a list of target PCs through the ClientsList (or via MSAD).
    Write-Debug -Message "Getting a list of targets from the ClientsList (or MSAD)." -Threshold 1 -Prefix '>>'
    $targets = Get-TargetClients -ClientsList $ClientsList
    # Get a list of client instances from the CliMonClient class, pre-instantiated.
    Write-Debug -Message "Getting client instances for the targets list." -Threshold 1 -Prefix '>>'
    $clients = 
        if($null -eq $targets -Or $targets.Length -lt 1) {
            throw("The script could not find a list of clients to target." +
                " Please check your configuration and try again.")
        } else { Get-ClientInstances -FromArray @($targets) }
    $clients = [System.Collections.ArrayList]@($clients)
    # The only reason "Get-ClientInstances" does NOT return an already-sorted and unique
    #  array of CliMonClient objects is in case anything is to be done with invalid objects
    #  as well, such as output of information during debug modes or at the end of the script.
    #
    # Get valid clients only, then use a custom pipeline function to return unique CliMonClient instances.
    Write-Debug -Message "ALL Client hostnames: $($clients.Hostname)" -Threshold 3 -Prefix '>>'
    [System.Collections.ArrayList]$global:CliMonClients =
        @($clients | Where-Object -Property IsValid -eq $True | Get-CliMonClientUnique)
    Write-Debug -Message "Unique & Valid client hostnames: $($global:CliMonClients.Hostname)" -Threshold 2 -Prefix '>>'
}



# Called directly from the main function as well.
#  Initializes each PS-Session for each client, and thereby gets the online/established bool
#  for each CliMonClient instance as well.
Function Start-Sessions() {
    Write-Host "`n`n`nStarting client sessions." -ForegroundColor Green
    # The reference for CliMonClient objects is the $global:CliMonClients list, so check it.
    if($null -eq $global:CliMonClients -Or
      ($global:CliMonClients -Is [System.Array] -And $global:CliMonClients.Length -lt 1)) {
        throw("There was an issue starting the sessions: there were no valid clients in the provided source.")
    }
    # Send out a single mass ping-check.
    Write-Debug -Message "Sending out a mass ping-check asynchronously." -Threshold 2 -Prefix '>>>>'
    $local:PingTasks = $global:CliMonClients.IpAddress | ForEach-Object {
        [System.Net.NetworkInformation.Ping]::new().SendPingAsync(
            $_,   #ping the target IP address
            1500,   #a 1500ms timeout
            (New-Object -TypeName Byte[] 32),   #a packet buffer of 32 bytes
            ([System.Net.NetworkInformation.PingOptions]::new(30, $False))   #TTL of 30, no fragmentation
        )
    }
    [Threading.Tasks.Task]::WaitAll($local:PingTasks)   #put the result into PingTasks.Result
    Write-Debug -Message "Establishing all PSSession objects simultaneously." -Threshold 2 -Prefix '>>>>'
    # Attempt to establish all sessions at once for all client hostnames.
    # If a localhost client is present in the list, specifically use 127.0.0.1. Else, use hostname.
    $local:targetClientNames = $global:CliMonClients | ForEach-Object {
        if($_.IsLocalhost()) { '127.0.0.1' } else { $_.Hostname }
    }
    $local:attemptedSessions =
        New-PSSession -ComputerName @($local:targetClientNames) -ErrorAction SilentlyContinue
    # Establish the sessions and set parameters/flags for each client in the list.
    foreach($client in $global:CliMonClients) {
        Write-Debug -Message "Examining client: $($client.Hostname)" -Threshold 3 -Prefix '>>>>>>'
        $local:pingTestResult = $local:PingTasks.Result `
            | Where-Object -Property Address -eq $client.IpAddress
        # If the ping is NOT successful...
        if($local:pingTestResult.Status -ne "Success") {
            Write-Debug -Message "The client is offline. Continuing to the next one." -Threshold 3 -Prefix '>>>>>>>>'
            # ... mark the client as offline; continue. 
            #  These (False values) are default, but this is for sanity.
            $client.Profile.IsOnline = $False
            $client.Profile.IsInvokable = $False
            continue   #onto the next
        } else {
            Write-Debug -Message "The client is online." -Threshold 3 -Prefix '>>>>>>>>'
            # The ping IS successful.
            $client.Profile.IsOnline = $True
            $local:clientSession = 
                if(-Not($client.IsLocalhost())) {
                    ($local:attemptedSessions `
                    | Where-Object -Property ComputerName -eq "$($client.Hostname)")
                } else {
                    ($local:attemptedSessions `
                    | Where-Object -Property ComputerName -eq "127.0.0.1")
                }
            # If the session is null or doesn't exist, the client doesn't have a session.
            if($null -eq $local:clientSession) {
                Write-Debug -Message "The client is NOT invokable, and has no valid session." -Threshold 3 -Prefix '>>>>>>>>'
                $client.SessionOpen = $False
                $client.ClientSession = $null
                $client.Profile.IsInvokable = $False
                continue
            } else {
                Write-Debug -Message "The client is invokable; session has been established." -Threshold 3 -Prefix '>>>>>>>>'
                $client.ClientSession = $local:clientSession
                $client.SessionOpen = $True
                $client.Profile.IsInvokable = $True
            }
        }
    }
    # Return nothing by default. This doesn't matter outside of the single-target mode.
    return $null
}



# Called directly from the main method.
#  Destroys/Hangs-up each established PS-Session for each client in this script.
Function Complete-Sessions() {
    Write-Host "`n`n`Terminating client sessions and cleaning objects." -ForegroundColor Green
    Write-Debug -Message "Terminating client sessions." -Threshold 1 -Prefix '>>'
    foreach($client in $global:CliMonClients) {
        Write-Debug -Message "Terminating the session for client: $($client.Hostname)" -Threshold 2 -Prefix '>>>>'
        if($null -ne $client.ClientSession -And
          $client.ClientSession -Is [System.Management.Automation.Runspaces.PSSession]) {
            Write-Debug -Message "A session is currently open for the client." -Threshold 3 -Prefix '>>>>>>'
            # Ensure the session is in the `Get-PSSession` table. (?)
            # Remove the session and nullify the variable.
            try {
                Write-Debug -Message "{Remove-PSSession -Session [client.session]}" -Threshold 4 -Prefix '>>>>>>'
                Remove-PSSession -Session $client.ClientSession
            } catch {
                # No need to do anything at this time. The error is most likely
                #  due to the fact that the session was terminated already.
                Write-Debug -Message "Failed to terminate/remove the PSSession object. Session is likely closed." `
                    -Threshold 3 -Prefix '>>>>>>'
            }
            Write-Debug -Message "Client session cleaned and marked as terminated." -Threshold 3 -Prefix '>>>>>>'
            $client.ClientSession = $null
            $client.SessionOpen = $False
        } else {
            # The session is already closed, or was never open.
            Write-Debug -Message "This client does not have a session; it is likely already closed." -Threshold 3 -Prefix '>>>>>>'
        }
    }
}



# Refresh the session state of the target machine. If, for whatever reason, the session has
#  closed where a previous session used to exist, then attempt to reopen it and provide the 
#  global Client Monitor config.
# This is only tried once each time it's discovered that a client's session has died.
Function Assert-SessionState() {
    param([Object]$TargetClient)
    if($null -ne $TargetClient.ClientSession -And
      $TargetClient.ClientSession.State -ne `
      [System.Management.Automation.Runspaces.RunspaceState]::Opened) {
        Write-Debug -Message "Attempting to re-assert the PSSession." -Threshold 1 -Prefix '>>'
        $local:successfulSession = $False
        $local:clientSession = $null
        # If the session state is NOT opened, but there was previously a session there,
        #  attempt to establish a new session and repopulate the global configuration.
        # This is effectively doing the same as Start-Sessions, but for a single client.
        $local:pingTask = [System.Net.NetworkInformation.Ping]::new().SendPingAsync($TargetClient.IpAddress)
        [System.Threading.Tasks.Task]::WaitAll($local:pingTask)
        if($local:pingTestResult.Status -ne "Success") {
            Write-Debug -Message "The client has gone offline." -Threshold 1 -Prefix '>>>>'
            # The client has crashed here many times. Awaiting another capture with this try/catch block enabled.
            try {
				$TargetClient.Profile.IsOnline = $False
			} catch {
				Write-Host "~~~~~~ Problem setting client Profile property IsOnline to FALSE. ~~~~~~"
				Write-Host "$($TargetClient | Format-List | Out-String)`n`n"
				Write-Host "$($TargetClient.Profile | Format-List | Out-String)"
				Write-Host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
				throw("$_ `n    ~~~~~~~~ Details should be logged.")
			}
            $local:successfulSession = $False
        } else { $TargetClient.Profile.IsOnline = $True }
        if($TargetClient.IsLocalhost() -eq $True -And $global:CliMonIsAdmin -eq $False) {
            Write-Debug -Message "The client is LOCALHOST and the script user is NOT a local administrator." -Threshold 1 -Prefix '>>>>'
            $local:successfulSession = $False
        }
        $local:clientSession =
            if(-Not($TargetClient.IsLocalhost())) {
                New-PSSession -ComputerName $TargetClient.Hostname -ErrorAction SilentlyContinue
            } else {
                New-PSSession '127.0.0.1' -ErrorAction SilentlyContinue
            }
        if($local:clientSession -IsNot [System.Management.Automation.Runspaces.PSSession] -Or
          $local:clientSession.State -ne [System.Management.Automation.Runspaces.RunspaceState]::Opened) {
            Write-Debug -Message "The new PSSession object cannot be started." -Threshold 1 -Prefix '>>>>'
            $local:successfulSession = $False
        } else { $local:successfulSession = $True }
        # Check if a successful session was established, and if so, capture it.
        #  Otherwise, set the client as dead/uninvokable.
        if($local:successfulSession -eq $True) {
            Write-Debug -Message "Session re-asserted successfully." -Threshold 1 -Prefix '>>>>'
            $TargetClient.Profile.IsInvokable = $True
            $TargetClient.ClientSession = $local:clientSession
            $TargetClient.SessionOpen = $True
            # Refresh the global variables within the client session.
            #  NOTE: This line is the reason that the "NoRefresh" switch is necessary
            #         within the Complete-RemoteOperations function, to prevent cascading errors.
            Write-Debug -Message "Attempting to reconfigure target global variables." -Threshold 2 -Prefix '>>>>>>'
            Set-AllClientConfigurationVariables -Clients @($TargetClient)
        } else {
            Write-Debug -Message "Session could not be re-asserted." -Threshold 1 -Prefix '>>>>'
            $TargetClient.Profile.IsInvokable = $False
            $TargetClient.ClientSession = $null
            $TargetClient.SessionOpen = $False
        }
    }
}



# Return a list of the clients that will be targeted, based on the Client Monitor ClientsList parameter.
#  This can either use the explicit parameter, or an MSAD-based list of users.
Function Get-TargetClients() {
    param([String]$ClientsList)
    if($ClientsList -eq "use-AD-list") {
        Write-Debug -Message "No ClientsList parameter is configured; using the directory to find clients." -Threshold 2 -Prefix '>>>>'
        # The "ClientsList" parameter wasn't set, implying to use MSAD w/ DomainFilter.
        try {
            Write-Debug -Message "{Get-ADComputer -Filter `"$($global:CliMonConfig.DomainUserFilter)`"}" -Threshold 3 -Prefix '>>>>'
            $local:clientNames = (Get-ADComputer -Filter $global:CliMonConfig.DomainUserFilter).Name
            $local:clientNames | ForEach-Object {
                Write-Debug -Message "Captured host: $_" -Threshold 4 -Prefix '>>>>>>'
            }
            return $local:clientNames
        } catch {
            Write-Host "~~~~ The Get-ADComputer cmdlet was tried, but didn't return any valid results."
            Write-Host "~~~~ Perhaps you should use a Clients List."
            return $null
        }
    } else {
        # The "ClientsList" parameter is manually set/passed. Find it, if possible, and import it.
        if(-Not(Test-Path $ClientsList)) {
            throw("The path provided for the 'ClientsList' parameter does not exist ($($ClientsList)).")
        }
        Write-Debug -Message "Collecting line-by-line clients from: $ClientsList" -Threshold 2 -Prefix '>>>>'
        return (Get-Content $ClientsList)
    }
}



# Complete the given ScriptBlock ($Actions) on all valid remote sessions simultaneously.
#
# A return value of $null implies there was an issue executing the ScriptBlock on the clients,
#  from the scope of the Complete-RemoteOperations command itself (not within a session).
#
# If the $NoRefresh flag is set, the "Assert-Session" function will not be called.
#  This is used in conjunction with the config import function to prevent endless loops.
Function Complete-RemoteOperations() {
    param([Object[]]$Clients, [ScriptBlock]$Actions,
        [Array]$Arguments, [Switch]$NoRefresh = $False)
    Write-Debug -Message "Running remote invocations." -Threshold 1 -Prefix '>>'
    # Cast the clients array to a flexible list type.
    $local:clientsList = [System.Collections.ArrayList]$Clients
    # Go through the list of clients and check if each session state is broken or disconnected.
    $local:origClientsLength = $Clients.Count
    for($i = 0; $i -lt $local:origClientsLength; $i++) {
        $client = $Clients[$i]
        if($null -eq $client) { continue }
        # If the client session was already marked as 'dead', just silently continue to the next.
        if($global:CliMonDeadSessions -IContains $client.Hostname) {
            Write-Debug -Message "Skipping session for client: $($client.Hostname)" -Threshold 1 -Prefix '>>>>'
            $local:clientsList.RemoveAt($i)
            continue
        }
        if($client.ClientSession.State `
          -ne [System.Management.Automation.Runspaces.RunspaceState]::Opened) {
            Write-Debug -Message "The client session is no longer valid for $($client.Hostname)." `
                -Threshold 1 -Prefix '>>>>'
            # Usually the $NoRefresh switch will only be set to prevent loops.
            if($NoRefresh -eq $False) { #-And $client.ClientSession.State) {
                Assert-SessionState -TargetClient $client
            } elseif($NoRefresh -eq $True) {
                Write-Debug -Message "The monitor is ordered NOT to re-assert. Nullifying session." `
                    -Threshold 1 -Prefix '>>>>'
                $client.ClientSession = $null
                $client.SessionOpen = $False
            }
            # If the session couldn't be re-established, pop the client off the target stack.
            #  Despite this being a modification of a reference, this is actually preferred since
            #  usually the Clients parameter will not reference the global CliMonClients array.
            if($client.SessionOpen -eq $False) {
                Write-Host ("~~~~ Couldn't maintain a valid session with client " +
                    "'$($client.Hostname)'. Ignoring this client and considering it dead.")
                $local:clientsList.RemoveAt($i)
                # Also need to remove the client from the global clients list, as they cannot have
                #  their session state re-asserted successfully. Also add them to the DeadSessions
                #  list to track later in notifications.
                try {
                    ($global:CliMonClients | Where-Object Hostname -eq $client.Hostname) | ForEach-Object { $global:CliMonClients.Remove($_) }
                } catch { }
                $global:CliMonDeadSessions += $client.Hostname
            }
        }
    }
    $local:Sessions = $local:clientsList.ClientSession
    try {
        $local:returnValue = Invoke-Command -ScriptBlock $Actions `
            -Session $local:Sessions -ArgumentList $Arguments
        # There should be processing here to capture results or other errors.
        return $local:returnValue
    } catch {
        Write-Error "~~~~ Could not execute the queries for the given sessions."
        return $null
    }
}