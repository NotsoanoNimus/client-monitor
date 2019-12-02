<#
 # ClientSessions.ps1
 #
 # Get, start, and remove all Client Monitor sessions.
 #  This script provides many of the startup and teardown methods.
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
            Write-Error ("The script could not find a list of clients to target." +
                " Please check your configuration and try again.")
            exit 2
        } else { Get-ClientInstances -FromArray @($targets) }
    # The only reason "Get-ClientInstances" does NOT return an already-sorted and unique
    #  array of CliMonClient objects is in case anything is to be done with invalid objects
    #  as well, such as output of information during debug modes or at the end of the script.
    #
    # Get valid clients only, then use a custom pipeline function to return unique CliMonClient instances.
    Write-Debug -Message "ALL Client hostnames: $($clients.Hostname)" -Threshold 3 -Prefix '>>'
    $global:CliMonClients = $clients | Where-Object -Property IsValid -eq $True | Get-CliMonClientUnique
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
        Write-Error "There was an issue starting the sessions: there were no valid clients in the provided source."
        exit 10
    }
    # Send out a single mass ping-check.
    Write-Debug -Message "Sending out a mass ping-check asynchronously." -Threshold 2 -Prefix '>>>>'
    $local:PingTasks = $global:CliMonClients.IpAddress | ForEach-Object {
        [System.Net.NetworkInformation.Ping]::new().SendPingAsync($_)
    }
    [Threading.Tasks.Task]::WaitAll($PingTasks)

    # Establish the sessions and set parameters/flags for each client in the list.
    foreach($client in $global:CliMonClients) {
        Write-Debug -Message "Examining client: $($client.Hostname)" -Threshold 3 -Prefix '>>>>>>'
        $local:pingTestResult = $local:PingTasks.Result | Where-Object -Property Address -eq $client.IpAddress
        # If the ping is NOT successful...
        if($local:pingTestResult.Status -ne "Success") {
            Write-Debug -Message "The client is offline. Continuing to the next one." -Threshold 3 -Prefix '>>>>>>>>'
            # ... mark the client as offline; continue. 
            #  These (False values) are default, but this is for sanity across this function.
            $client.Profile.IsOnline = $False
            $client.Profile.IsInvokable = $False
            continue   #onto the next
        } else {
            Write-Debug -Message "The client is online." -Threshold 3 -Prefix '>>>>>>>>'
            # The ping IS successful.
            $client.Profile.IsOnline = $True
            $clientSession = $null
            try {
                Write-Debug -Message "Client is a Localhost client: $($client.IsLocalhost())" -Threshold 3 -Prefix '>>>>>>>>'
                # Try to establish a session using the client's hostname, if the client isn't localhost.
                if(-Not($client.IsLocalhost())) {
                    Write-Debug -Message "Attempting a session with the client." -Threshold 3 -Prefix '>>>>>>>>'
                    $clientSession = New-PSSession -ComputerName $client.Hostname -ErrorAction SilentlyContinue
                }
                # If it didn't work (but no error was caught), still keep things false appropriately.
                if(-Not($client.IsLocalhost()) -And
                  $clientSession -IsNot [System.Management.Automation.Runspaces.PSSession]) {
                    Write-Debug -Message "The PSSession failed; client is NOT invokable." -Threshold 3 -Prefix '>>>>>>>>'
                    $client.Profile.IsInvokable = $False
                } else {
                    Write-Debug -Message "The PSSession is established. Marking the client as reachable." -Threshold 3 -Prefix '>>>>>>>>'
                    # Otherwise, set the ClientSession value, and show invokability is True.
                    $client.ClientSession = $clientSession
                    $client.Profile.IsInvokable = $True
                    $client.SessionOpen = $True
                }
            } catch {
                Write-Debug -Message "An error was caught during session establishment. Marking the client as unreachable." `
                    -Threshold 3 -Prefix '>>>>>>>>'
                $client.Profile.IsInvokable = $False
            }
        }
    }
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



# Return a list of the clients that will be targeted, based on the Client Monitor ClientsList parameter.
#  This can either use the explicit parameter, or an MSAD-based list of users.
Function Get-TargetClients() {
    param([String]$ClientsList)
    if($ClientsList -eq "use-AD-list") {
        Write-Debug -Message "No ClientsList parameter is configured; using the directory to find clients." -Threshold 2 -Prefix '>>>>'
        # The "ClientsList" parameter wasn't set, implying to use MSAD w/ DomainFilter.
        try {
            Write-Debug -Message "{Get-ADComputer -Filter `"$($global:CliMonConfig.DomainUserFilter)`"}" -Threshold 3 -Prefix '>>>>'
            $local:clientNames = Get-ADComputer -Filter $global:CliMonConfig.DomainUserFilter `
                | Select-Object -Property Name
            $local:clientNames | ForEach-Object {
                Write-Debug -Message "Captured host: $_" -Threshold 4 -Prefix '>>>>>>'
            }
            return $local:clientNames
        } catch { return $null }
    } else {
        # The "ClientsList" parameter is manually set/passed. Find it, if possible, and import it.
        if(-Not(Test-Path $ClientsList)) {
            Write-Error "The path provided for the 'ClientsList' parameter does not exist ($($ClientsList))."
            exit 4
        }
        Write-Debug -Message "Collecting line-by-line clients from: $ClientsList" -Threshold 2 -Prefix '>>>>'
        return (Get-Content $ClientsList)
    }
}