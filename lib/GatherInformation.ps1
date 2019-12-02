<#
 # GatherInformation.ps1
 #
 # All functions pertinent to collecting information from the target client,
 #  to fill out the client's "profile" object.
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



# Called from the main routine. Get the CURRENT state of all connected clients,
#  and generate/output the client reports.
Function Get-CurrentEnvironment() {
    Write-Host "`n`n`nGathering all client information and populating profiles." -ForegroundColor Green
    foreach($client in $global:CliMonClients) {
        # The 'client' variable is always passed as a reference/pointer, so it can be
        #  modified WITHOUT copying the data and returning the manipulated copy.
        Write-Host "`n`nHostname: " -NoNewline
        Write-Host "$($client.Hostname)" -ForegroundColor Cyan
        Write-Host "IP Address: " -NoNewline
        Write-Host "$($client.IpAddress)" -ForegroundColor Cyan
        # Interpret the client's online/invokability status. If the client is not online
        #  or couldn't be invoked, then check for a prior report and propagate it forward.
        Write-Debug -Message "Getting the target's reachability." -Threshold 1 -Prefix '>>'
        $local:skipToNext = Get-ClientStatus -TargetClient $client
        if($local:skipToNext -eq $True) { continue }
        # Populate the target session with the global Client Monitor Configuration object.
        #  If importing the config on the remote client fails, propagate the report and
        #  continue with processing the next client.
        $local:successfulImport = Set-ClientConfigurationVariables -TargetClient $client
        if($local:successfulImport -eq $False) { continue }
        # Mount the registry endpoints for each user on the remote machine.
        Mount-UserHives -TargetClient $client
        # Fill out the $client.Profile variable.
        Get-ClientProfile -TargetClient $client
        # Filename tracking must be done AFTER getting the client profile, due to the way
        #  the profile is returned from the remote session in the previous step.
        if($global:CliMonConfig.FilenameTracking.Enabled -eq $True) {
            # File tracking is handled separately from the profile (even though it's part
            #  of it), because it is a very complicated feature that was added well after
            #  the other Profile items, and is thus much different.
            # This is mostly for the ease of maintenance and bugfixes.
            Get-ClientTrackedFiles -TargetClient $client
        }
        # Write the $client.Profile object to a JSON report.
        Write-ClientReport -TargetClient $client
        # Unmount any user hives that were mounted earlier.
        Remove-UserHives -TargetClient $client
    }
    # If enabled, generate the flat report CSV as an aggregate report of all Client Profiles.
    if($FlatReportCsv -eq $True) { Write-CliMonFlatReport }
}




# Check the client's online status. If the client object shows the client as unreachable,
#  then search for a recent written report and move it forward.
Function Get-ClientStatus() {
    param([Object]$TargetClient)
    Write-Host "-- Getting client status."
    # This is a bit disconcerting: calling this method (from CompareData.ps1) is getting
    #  any existing PRIOR report, meaning a report from a previous run of the script, for
    #  this client. Ordinarily, the switch "IsPrior" is used to fetch the second-to-top of
    #  the most recent reports. Since this step is called BEFORE the comparison section, a
    #  report from this run of the script hasn't yet been written, so it won't use the switch.
    Write-Debug -Message "Retrieving the Prior report information, if it exists." -Threshold 2 -Prefix '>>>>'
    $local:priorReport = Get-ClientReport -TargetClient $TargetClient
    # Add special properties for use later in the notification generation section.
    #  If there's a prior report, the variable is set based on the differences between now and then.
    #  Otherwise, a change can't be detected (as there's nothing to compare), so it's set to $False.
    #  These variables show which part of the reachability has changed, if any.
    $local:onlineStatusChange =
        if($null -ne $local:priorReport) {
            ($TargetClient.Profile.IsOnline -ne $local:priorReport.IsOnline)
        } else { $False }
    $local:invokableStatusChange =
        if($null -ne $local:priorReport) {
            ($TargetClient.Profile.IsInvokable -ne $local:priorReport.IsInvokable)
        } else { $False }
    Write-Debug -Message "Online Status Change: $($local:onlineStatusChange)" -Threshold 3 -Prefix '>>>>>>'
    Write-Debug -Message "Invokable Status Change: $($local:invokableStatusChange)" -Threshold 3 -Prefix '>>>>>>'
    # If the client is now not reachable, propagate the previous report forward.
    #  Otherwise, just track the reachability change and move forward.
    if($TargetClient.Profile.IsOnline -eq $False -Or
      $TargetClient.Profile.IsInvokable -eq $False) {
        Write-Host ("**** A session couldn't be established to the client; " +
            "new changes cannot be tracked.")
        Write-Host ("****  Copying the most recent report (if it exists) forward " +
            "to preserve the client's last known state.")
        if($null -ne $local:priorReport) {
            # A prior report was fetched, propagate it forward.
            Write-Debug -Message "A prior report was fetched; propagating it forward due to unreachability." -Threshold 3 -Prefix '>>>>'
            $TargetClient.Profile = $local:priorReport
        }
        $TargetClient.Profile.OnlineStatusChange = $local:onlineStatusChange
        $TargetClient.Profile.InvokableStatusChange = $local:invokableStatusChange
        # Write the report, with either the blank profile or the prior profile.
        Write-ClientReport -TargetClient $TargetClient
        # No matter what, the client is unreachable; send a signal back to skip info gathering.
        return $True
    } else {
        Write-Debug -Message "The target client is online and reachable. Continuing." -Threshold 3 -Prefix '>>>>'
        # Set the properties and continue getting the client's information.
        $TargetClient.Profile.OnlineStatusChange = $local:onlineStatusChange
        $TargetClient.Profile.InvokableStatusChange = $local:invokableStatusChange
        return $False
    }
}

# Populate the target session with the global Client Monitor Configuration object.
#  This is a clever way to avoid relative-path sourcing on the target by passing over
#  what the primary process already knows.
Function Set-ClientConfigurationVariables() {
    param([Object]$TargetClient)
    Write-Host "-- Connecting to the client session and populating global configuration values."
    [ScriptBlock]$local:doPopulateConfig = {
        param([Object]$GlobalConfig)
        # Set the global configuration variables.
        $global:CliMonConfig = $GlobalConfig
        # Define the Write-Debug function on the target client. See the script declaration for this
        #  function in the Miscellaneous.ps1 library file for a commented version of the same.
        Function Write-Debug() {
            param([int]$Threshold = 10000, [String]$Message, [String]$Prefix = "")
            if($Threshold -le $global:CliMonConfig.Verbosity) {
                & Write-Host "[$Threshold] " -ForegroundColor Yellow -BackgroundColor Black -NoNewline
                & Write-Host "$($Prefix) " -ForegroundColor Cyan -BackgroundColor Black -NoNewline
                # The target-side definition of debug includes this line because Write-Debug calls on the
                #  client endpoint are always 'invoked'. This is good to know WHERE a command is executed.
                & Write-Host "[INVOKE] " -ForegroundColor White -BackgroundColor Black -NoNewline
                & Write-Host "$Message" -ForegroundColor Magenta -BackgroundColor Black
            }
        }
        Write-Debug -Message "Defined {Write-Debug} on the target client." -Threshold 3 -Prefix '>>>>'
        Write-Debug -Message "Defined {global:CliMonConfig} on the target client." -Threshold 2 -Prefix '>>>>'
        # Return the status of the configuration import variable. If it returns $True, the client
        #  successfully imported the Client Monitor configuration information.
        return $global:CliMonConfig.ConfigImported
    }
    $local:importResult = $TargetClient.RemoteCommand($local:doPopulateConfig, @($global:CliMonConfig))
    if($local:importResult.Success -eq $True) {
        if($local:importResult.Result -eq $False) {
            # Despite an apparently-successful invocation, there's an issue setting the config on the
            #  remote endpoint. The script can't proceed with this client if this occurs.
            Show-ConfigImportFailure -TargetClient $TargetClient
            return $False
        } else {
            Write-Host "---- Configuration successfully imported to the remote session."
            return $True
        }
    } else {
        # Something broke on the target. This block implies that the invoke itself failed.
        #  It could be a slightly different action than above, but it's likely this client
        #  will have to be ignored.
        Show-ConfigImportFailure -TargetClient $TargetClient
        return $False
    }
}
# Helper function for the above method. Shown if for any reason the import fails.
Function Show-ConfigImportFailure() {
    param([Object]$TargetClient)
    Write-Host "~~~~ Failed to import the global configuration into the remote session."
    Write-Host "~~~~ Skipping this client and propagating the previous report forwards, if it exists."
    # This is doing the same as in the Get-ClientStatus function. Please reference that section.
    Write-Debug -Message "Retrieving the Prior report information, if it exists." -Threshold 2 -Prefix '>>>>'
    $local:priorReport = Get-ClientReport -TargetClient $TargetClient
    # Keep the status change in-tact though.
    $local:onlineStatus = $TargetClient.Profile.OnlineStatusChange
    $local:invokableStatus = $TargetClient.Profile.InvokableStatusChange
    if($null -ne $local:priorReport) {
        # A prior report was fetched, propagate it forward.
        Write-Debug -Message "A prior report was fetched; propagating it forward due to failure to import global configuration." `
            -Threshold 3 -Prefix '>>>>>>'
        $TargetClient.Profile = $local:priorReport
        # Since the profile's overwritten, use the local variables above to keep the information about
        #  status changes in-tact, in case it's changed in any way.
        $TargetClient.Profile.OnlineStatusChange = $local:onlineStatus
        $TargetClient.Profile.InvokableStatusChange = $local:invokableStatus
    } else {
        Write-Debug -Message "No prior report was found; writing a blank profile as the report." -Threshold 3 -Prefix '>>>>>>'
    }
    # Write the report, with either the blank profile or the prior profile.
    Write-ClientReport -TargetClient $TargetClient
}



# Mount the user registry hives onto the local machine, for analysis by Client Monitor.
Function Mount-UserHives() {
    param([Object]$TargetClient)
    Write-Host "-- Mounting user registry hives."
    # Create the remote ScriptBlock, which will return an Array object indicating the hives
    #  present/mounted on the client machine.
    [ScriptBlock]$local:doMountHives = {
        # Get a list of the user profiles, stored into the userProfiles variable.
		#  This method uses the $UserProfileBase configuration variable as a FALLBACK option.
        $UserProfileDirectory = (
            Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\'
        ).ProfilesDirectory
        if($null -eq $UserProfileDirectory) {
            $UserProfileDirectory = $global:CliMonConfig.UserProfileBase
        }
        Write-Debug -Message "User Profile Directory: $UserProfileDirectory" -Threshold 3 -Prefix '>>>>'
        $userProfiles = (Get-ChildItem -Path "$UserProfileDirectory" -Directory `
            | Where-Object -Property Name -NotMatch '^Public$').FullName
        Write-Debug -Message "Target's user profiles list:" -Threshold 2 -Prefix '>>>>'
        $userProfiles | ForEach-Object {
            Write-Debug -Message "$_" -Threshold 2 -Prefix '>>>>>>'
        }
        # Sanity check on the result above. Make sure there is at least one result.
        if($null -eq $userProfiles -Or 
          ($userProfiles -Is [System.Array] -And $userProfiles.Length -lt 0)) {
            # Warn somehow that per-user hives aren't mounted (and won't be tracked)
            Write-Host ("~~~~ COULD NOT GET A LIST OF TARGET PROFILES. " +
                "WILL NOT TRACK PER-USER ITEMS FOR THIS CLIENT.")
            return @()   #return an empty list of mounted hives.
        }
        Write-Debug -Prefix '>>' -Message "Got user profile list: $($userProfiles)" -Threshold 1
        # Moving on... test the shadow location. If it doesn't exist, create the directory and force
        #  admin-only access controls on the folder.
        if(-Not(Test-Path -Path $global:CliMonConfig.NTUSERShadowLocation)) {
            New-Item -Path "$($global:CliMonConfig.NTUSERShadowLocation)" -ItemType Directory
            if($? -eq $False) {
                # Warn somehow that per-user hives aren't mounted (and won't be tracked)
                Write-Host ("~~~~ COULD NOT CREATE A DIRECTORY TO SHADOW USER HIVES. " +
                    "WILL NOT TRACK PER-USER ITEMS FOR THIS CLIENT.")
                return @()   #return an empty list of mounted hives.
            }
            # TODO: Add admin-only ACLs to the folder.
        }

        # Doing ANYTHING possible to avoid starting CMD.EXE with a UNC path.
        Push-Location -Path $global:CliMonConfig.NTUSERShadowLocation
        if($? -ne $True) { Push-Location -Path "C:\" }
        Write-Debug "Changed directory (for CMD.EXE safety): $((Get-Location).Path)" -Threshold 4 -Prefix '>>>>'
        # Go through each profile, shadow the NTUSER hive, and mount it onto the registry.
        $mountedHives = @()
        foreach($profile in ($userProfiles | Sort-Object)) {
            Write-Debug -Message "Examining profile: $profile" -Threshold 2 -Prefix '>>>>'
            # Get the username from the folder structure.
            $username = Split-Path -Path "$($profile)" -Leaf
            # Set up the shadow location for the NTUSER file (in case the hive isn't mounted).
            $hiveFile = "$($global:CliMonConfig.NTUSERShadowLocation)\\NTUSER.DAT_$($username)"
            try {
                # Attempt the copy-file operation.
                Write-Debug -Threshold 2 -Prefix '>>>>>>' -Message ("Attempting NTUSER.DAT copy operation:" +
                    " $($profile)\\$($global:CliMonConfig.NTUSERLocation)\\NTUSER.DAT ----> $hiveFile")
                Copy-Item -Path "$($profile)\\$($global:CliMonConfig.NTUSERLocation)\\NTUSER.DAT" `
                    -Destination $hiveFile -Force
                Write-Debug -Message "Copy successful." -Threshold 2 -Prefix '>>>>>>>>'
                # If the operation is successful, duplicate ACLs and use CMD "reg" to mount the hive.
                #  If there was an error copying the file, that means the user is logged in and the hive is locked.
                # Sanity-check ...again. Check the file.
                if(-Not(Test-Path -Path $hiveFile)) {
                    Write-Host ("~~~~ Could not find or access the shadow hive file, " +
                        "despite it being copied successfully. Skipping...")
					continue
                }
                # Quickly set the NTUSER.DAT ACLs to its original content.
                Write-Debug -Message "Copying access control / permissions from the original file." `
                    -Threshold 3 -Prefix '>>>>>>>>'
                Get-Acl "$($profile)\\$($global:CliMonConfig.NTUSERLocation)\\NTUSER.DAT" | Set-Acl $hiveFile
                try {
                    # Attempt to mount the hive.
                    Write-Debug -Message "Attempting CMD.EXE call: reg load HKU\CLI-MON-$($username) `"$hiveFile`"" `
                        -Threshold 2 -Prefix '>>>>>>'
                    reg load "HKU\CLI-MON-$($username)" `"$hiveFile`" | Out-Null
                    # Index the mounted hive, provided the load was successful.
                    if($? -eq $True) {
                        $mountedHives += "$($global:CliMonConfig.DomainName)\$($username)"
                        Write-Debug "Success!" -Threshold 2 -Prefix '>>>>>>>>'
                        Write-Debug -Threshold 1 -Prefix '++++++++++' -Message ("Added user to mountedHives for $($username): " +
                            "$($global:CliMonConfig.DomainName)\$($username)")
                    }   # TODO: Add an "else" block here to handle failures.
                } catch {
                    Write-Debug -Message "Failed to mount the user hiveFile at: $hiveFile" -Threshold 1 -Prefix '>>>>>>'
                }
            } catch {
                # This will likely be caught in the event the file-copy operation fails.
                Write-Debug -Message "Failed to copy the user's NTUSER.DAT to: $hiveFile" -Threshold 3 -Prefix '>>>>>>'
                # Check if the user's profile name is already mounted under "CLI-MON-[username]".
				$profilesMounted = (Get-ChildItem "REGISTRY::HKU" `
                    | Where-Object -Property PSChildName -Like "CLI-MON-*").PSChildName
                if($null -ne $profilesMounted -And $profilesMounted.Contains("CLI-MON-$username")) {
                    Write-Debug -Message "The user has a CLI-MON hive already loaded: HKU\CLI-MON-$username" `
                        -Threshold 3 -Prefix '>>>>>>>>'
                    # If the user has a CLI-MON mountpoint already, add them and move on.
                    $mountedHives += "$($global:CliMonConfig.DomainName)\$($username)"
                    Write-Debug -Threshold 1 -Prefix '++++++++++' -Message ("Added user to mountedHives for $($username): " +
                        "$($global:CliMonConfig.DomainName)\$($username)")
                } else {
                    Write-Debug -Message "Checking if the user is currently logged on." -Threshold 3 -Prefix '>>>>>>>>'
                    # If the user does NOT have a CLI-MON mountpoint, the SID is likely already loaded.
                    $userObject = if($global:CliMonConfig.DomainName -ne "") {
                        New-Object System.Security.Principal.NTAccount(
                            $global:CliMonConfig.DomainName, $username
                        )
                    } else { New-Object System.Security.Principal.NTAccount($username) }
                    $userSID = $userObject.Translate([System.Security.Principal.SecurityIdentifier])
                    Write-Debug -Message "Added already-mounted user SID: $userSID" -Threshold 4 -Prefix '>>>>>>>>>>'
                    $mountedHives += "$($userSID)"
                    Write-Debug -Threshold 1 -Prefix '++++++++++' -Message ("Added user SID to mountedHives for $($username): " +
                        "$($global:CliMonConfig.DomainName)\$($username)")
                }
            }
        }
        # Return to the original directory and return the list of mounted hives.
        Pop-Location
        Write-Debug "Reverted directory: $((Get-Location).Path)" -Threshold 4 -Prefix '>>>>'
        return $mountedHives
    }
    # Invoke the ScriptBlock in the remote session.
    $local:mountResults = $TargetClient.RemoteCommand($local:doMountHives, $null)
    if($local:mountResults.Success -eq $True) {
        # Success.
        $local:mountResults.Result | ForEach-Object {
            Write-Host "---- Prepared Registry Hive: " -NoNewline
            Write-Host "$_" -ForegroundColor Yellow
        }
    } else {
        # Failure.
        Write-Host "~~~~ FAILED TO MOUNT THE USER HIVES FOR CLIENT: " -NoNewline
        Write-Host "$($TargetClient.Hostname)" -ForegroundColor Cyan
        # Possibly add a flag to ignore ANY CHANGES FOR PER-USER INFORMATION!!!
    }
}

# Dismount the previously-mounted registry hives, and clean up any leftover information.
Function Remove-UserHives() {
    param([Object]$TargetClient)
    Write-Host "-- Unmounting user hives previously mounted by the script."
    [ScriptBlock] $local:doDismountHives = {
        # Doing ANYTHING possible to avoid starting CMD.EXE with a UNC path.
        Push-Location -Path $global:CliMonConfig.NTUSERShadowLocation
        if($? -ne $True) { Push-Location -Path "C:\" }
        Write-Debug "Changed directory (for CMD.EXE safety): $((Get-Location).Path)" -Threshold 4 -Prefix '>>>>'
        # Get a list of all hives mounted by Client Monitor (CLI-MON-*).
        # NOTE: Though we could recycle the "mountedHives" variable here from earlier,
        #  since it's the same session, it doesn't matter because while that first list
        #  of hives is >every< mounted hive, the below is extracting ONLY hives that have
        #  been specifically mounted by Client Monitor, and NOT the operating system.
        $mountedHives = (Get-ChildItem "REGISTRY::HKU" `
            | Where-Object -Property PSChildName -Like "CLI-MON-*").Name `
            | ForEach-Object { $_ -Replace "HKEY_USERS", "HKU" }
        # For each hive in the array, attempt to unmount it.
        if(($mountedHives -Is [Array] -And $mountedHives.Length -gt 0) -Or
          ($null -ne $mountedHives -And "" -ne $mountedHives)) {
            $mountedHives | ForEach-Object {
                $local:didDismount = $False
                $local:i = 0
                for(; $local:i -lt 5; $local:i++) {
                    try {
                        # Attempt to unload. If something is caught, the script will pause and try again.
                        Write-Debug -Message "Attempting to dismount hive: $_" -Threshold 1 -Prefix '>>>>'
                        reg unload $_ 2>&1 | Out-Null
                        $local:didDismount = $True
                        Write-Debug -Message "Succeeded." -Threshold 1 -Prefix '>>>>>>'
                        # Escape the loop.
                        $local:i = 500
                    } catch {
                        # If there was a problem, retry after 2 seconds.
                        Write-Debug -Message "Failed." -Threshold 1 -Prefix '~~~~~~'
                        Start-Sleep -Seconds 2
                    }
                }
                # Output the result of the dismount.
                Write-Host "---- Node: $_   [" -NoNewline
                if($local:didDismount -eq $True) { Write-Host "SUCCESS" -ForegroundColor Green -NoNewline }
                else { Write-Host "FAILURE" -ForegroundColor Red -NoNewline }
                Write-Host "]"
            }
        } else {
            Write-Host "---- No hives seem to have been mounted."
        }
        # Return to the original directory.
        Pop-Location
        Write-Debug "Reverted directory: $((Get-Location).Path)" -Threshold 4 -Prefix '>>>>'
    }
    # Invoke the ScriptBlock in the remote session.
    $local:dismountResults = $TargetClient.RemoteCommand($local:doDismountHives, $null)
}



# Write the finished CliMonClient Profile object into a report.
Function Write-ClientReport() {
    param([Object]$TargetClient)
    Write-Host "-- Finalizing the generated client profile report."
    # If Snapshot Mode is enabled, leave without writing anything.
    if($SnapshotMode -eq $True) {
        Write-Host "~~ Snapshot Mode is currently enabled. Skipping report generation."
        return
    }
    # Today's date, format of YYYY-MM-DD-HH_MM
    $local:dateTag = Get-Date -UFormat %Y-%m-%d-%H_%M
    $local:targetFile = ('{0}\Report-{1}-{2}.txt' `
        -f $global:CliMonConfig.ReportsDirectory, $TargetClient.Hostname, $local:dateTag)
	# Write the output as a JSON object to the report file (targetFile).   
	try {
        Write-Output $TargetClient.Profile `
            | ConvertTo-Json -Depth 3 -Compress:$CompressJSON `
            | Out-File -FilePath $local:targetFile
        # Add the path to the report to the index of reports generated by this run of the script.
        $global:CliMonGeneratedReports += $local:targetFile
        Write-Debug -Message "Successfully wrote target client report at: $($local:targetFile)" -Threshold 2 -Prefix '>>>>'
	} catch {
		Write-Error "There was an issue writing report: $($local:targetFile). $_. Aborting script."
		throw("Could not write to the Reports Directory for client: $($TargetClient.Hostname)")
    }
}



# Write the flat report CSV to the output file and track the name.
#  The 'Flat Report' is a CSV file that contains all client environment information. It is a CSV
#  equivalent of the "snapshot mode" option for Client Monitor.
Function Write-CliMonFlatReport() {
    Write-Host "`n`n`nGenerating flat CSV report. This might take a significant amount of time..." -ForegroundColor Yellow
    $local:flatReportContents = @()
    $local:reportedKeys = @("InstalledApps", "StoreApps", "Services", "ScheduledTasks", "StartupApps")
    Write-Debug -Message "Reported Keys to squash for flat reporting: $($local:reportedKeys)" -Threshold 4 -Prefix '>>'
    # Get all columns from "TrackedValues". plus the static column names from above, and put them into
    #  one array. Then, go through the ColumnOrder as defined by the user, and expand any instances
    #  of the 'wildcard' character with the columns from the compiled array that are NOT defined in the
    #  column order variable. This is to prevent duplicate variable selection while also leaving the
    #  properties in-tact.
    # Since the final collection of custom objects varies in property type, doing a Get-Member for the
    #  NoteProperty type will ONLY return the properties from the first object in the array (which isn't
    #  all of them), so the TrackedValues section needs to be evaluated and unique Column names need to
    #  be added onto the final "columns" array that will be sent forward.
    $local:allCsvColumns = [System.Collections.ArrayList]@()
    foreach($key in $local:reportedKeys) {
        $global:CliMonConfig.TrackedValues.$key | ForEach-Object {
            if($local:allCsvColumns -INotContains $_) { $local:allCsvColumns += $_ }
        }
    }
    $local:allCsvColumns += [System.Collections.ArrayList]@("Category", "Hostname",
        "IpAddress", "Online", "Invokable", "KeyName")
    $local:allCsvColumns = [System.Collections.ArrayList]$local:allCsvColumns
    # Also create a copy of the "all columns" array to reference as things are scanned from the
    #  ColumnOrder variable. If an item in ColumnOrder shows up that isn't listed in this array,
    #  do NOT generate the CSV report, and issue a warning of the bad configuration. Note that the
    #  wildcard character is not added to this (because it's skipped in the loop).
    $local:allCsvColumnsAuthoritative = [Array]$local:allCsvColumns
    Write-Debug -Message "Authoritative columns: $($local:allCsvColumnsAuthoritative)" -Threshold 4 -Prefix '>>>>'
    # For each column already defined in the ColumnOrder variable, remove it from the allCsvColumns
    #  variable if it's already been listed.
    foreach($column in $global:CliMonConfig.FlatReportCsv.ColumnOrder) {
        if($local:allCsvColumns -Contains $column) {
            # Pop the column name from the list of CSV columns.
            $local:allCsvColumns.Remove([String]$column)
            Write-Debug -Message "Popped column from allCsvColumns: $column" -Threshold 4 -Prefix '>>'
        }
        # Check against the 'authority' array.
        if($local:allCsvColumnsAuthoritative -CNotContains $column -And $column -ne '*') {
            Write-Host ("~~ Failed to write the CSV report: The ColumnOrder setting" +
                " contains invalid column names.") -ForegroundColor Red
            Write-Host ("~~~~ Please check your configuration. The values are CASE SENSITIVE. " +
                "The problem column name was: '$column'") -ForegroundColor Red
            return
        }
    }
    # Search for a wildcard in the list of column ordering. Limit it to ONE only.
    $local:wildcardEncountered = $False
    $local:originalColumnOrderLength = $global:CliMonConfig.FlatReportCsv.ColumnOrder.Length
    Write-Debug -Message "Expanding any wildcards into the list of non-included column names, in an arbitrary order." `
        -Threshold 1 -Prefix '>>'
    for($local:i = 0; $local:i -lt $local:originalColumnOrderLength; $local:i++) {
        # If a wildcard was already encountered, no processing is needed.
        if($local:wildcardEncountered -eq $True) { continue }
        elseif ($global:CliMonConfig.FlatReportCsv.ColumnOrder[$local:i] -eq '*') {
            Write-Debug -Message "Encountered a wildcard in the ColumnOrder configuration at index $($local:i)" `
                -Threshold 3 -Prefix '>>>>'
            # Splice the allCsvColumns variable into this location by splitting up the array
            #  and reassigning the variable.
            $local:columnOrderShadow = $global:CliMonConfig.FlatReportCsv.ColumnOrder
            $global:CliMonConfig.FlatReportCsv.ColumnOrder = @()
            $global:CliMonConfig.FlatReportCsv.ColumnOrder = $local:columnOrderShadow[0..($local:i-1)]
            $global:CliMonConfig.FlatReportCsv.ColumnOrder += $local:allCsvColumns
            # Only add the backing portion of the array if the wildcard isn't the LAST item in the list.
            if(($local:i + 1) -lt $local:originalColumnOrderLength) {
                $global:CliMonConfig.FlatReportCsv.ColumnOrder +=
                    $local:columnOrderShadow[($local:i+1)..($local:originalColumnOrderLength)]
            }
            $local:wildcardEncountered = $True
        }
    }
    # Run the final test against the authority after expansion. This is a safety measure.
    #  This time the test will NOT allow wildcards (since it should have been expanded); this
    #  prevents a user from adding two or more wildcards to the ColumnOrder variable.
    foreach($column in $global:CliMonConfig.FlatReportCsv.ColumnOrder) {
        if($local:allCsvColumnsAuthoritative -CNotContains $column) {
            Write-Host ("~~ Failed to write the CSV report: The ColumnOrder setting" +
                " contains invalid column names.") -ForegroundColor Red
            Write-Host ("~~~~ Please check your configuration. The values are CASE SENSITIVE. " +
                "The problem column name was: '$column'") -ForegroundColor Red
            return
        }
    }
    Write-Debug -Threshold 1 -Prefix '>>>>' -Message ("Reported columns, by order (left-to-right)" +
        ": $($global:CliMonConfig.FlatReportCsv.ColumnOrder)")
    # Go through each client and get the contents of each profile to generate the report.
    foreach($client in $global:CliMonClients) {
        Write-Debug -Message "Flattening client: $client" -Threshold 2 -Prefix '>>'
        foreach($key in $local:reportedKeys) {
            Write-Debug -Message "Reported Key (item type): $key" -Threshold 2 -Prefix '>>>>'
            # Get the corresponding index for the key, the run a foreach on the list.
            $local:listOfKeyItems = $client.Profile."$($key)Index"
            foreach($listItem in $local:listOfKeyItems) {
                Write-Debug -Message "Examining index key for type $($key): $listItem" -Threshold 3 -Prefix '>>>>>>'
                $local:clientProfileContents = @{}
                # On each item, add each key to the result hashtable object, then append that final
                #  information to the flatReportContent array.
                $local:nodeProperties =
                    ($client.Profile.$key.$listItem | Get-Member -Type NoteProperty).Name
                foreach($listItemKey in $local:nodeProperties) {
                    Write-Debug -Message "Squashing property $listItemKey." `
                        -Threshold 4 -Prefix '>>>>>>>>'
                    # Replace the delimiter character (if it appears) according to the config.
                    $local:listItemContent = $client.Profile.$key.$listItem.$listItemKey -Replace `
                        [Regex]::Escape($global:CliMonConfig.FlatReportCsv.Delimiter),
                        $global:CliMonConfig.FlatReportCsv.DelimiterReplacement
                    # If the property/column name is "Name" or "TaskName" convert it to "DisplayName"
                    #  Otherwise, just set it to the key (no change)...
                    $local:listItemTableKey =
                        if($listItemKey -eq "Name" -Or $listItemKey -eq "TaskName") { "DisplayName" }
                        else { $listItemKey }
                    # This is just copying the hashtable over, so properties can be added.
                    $local:clientProfileContents.Add($local:listItemTableKey, $local:listItemContent)
                }
                # If the set of member properties doesn't contain one of the "Name" columns, set
                #  the DisplayName field to the listItem variable. This is usually just the case for
                #  startup apps but it's made dynamically in case the selected property fields changes.
                if($local:nodeProperties -INotContains "DisplayName" -And
                  $local:nodeProperties -INotContains "TaskName" -And
                  $local:nodeProperties -INotContains "Name") {
                    $local:clientProfileContents.Add("DisplayName", $listItem)
                }
                # Adding other custom properties... This is to make the nested JSON report object flat.
                $local:clientProfileContents.Add("Category", $key)
                $local:clientProfileContents.Add("Hostname", $client.Hostname)
                $local:clientProfileContents.Add("IpAddress", $client.IpAddress)
                $local:clientProfileContents.Add("Online", $client.Profile.IsOnline)
                $local:clientProfileContents.Add("Invokable", $client.Profile.IsInvokable)
                $local:clientProfileContents.Add("KeyName", $listItem)
                Write-Debug -Message "Spliced on custom attributes to the flat object." -Threshold 4 -Prefix '>>>>>>>>'
                # Add the final object onto the final array.
                $local:flatReportContents += [PSCustomObject]$local:clientProfileContents
                Write-Debug -Message "Added the flattened $listItem to the final report collection." -Threshold 3 -Prefix '++++++++'
            }
        }
    }
    # If the list of columns to select includes the "TaskName" and "Name" columns, they should be
    #  omitted from the results since they will always be blank. This is due to the above renaming
    #  that was done during the Profile parsing.
    # NOTE: A Remove call will NOT throw an error if the string doesn't exist in the array.
    $local:columnOrderShadow2 = 
        [System.Collections.ArrayList]$global:CliMonConfig.FlatReportCsv.ColumnOrder
    @("TaskName", "Name") | ForEach-Object {
        if($local:columnOrderShadow2 -CContains $_) { $local:columnOrderShadow2.Remove($_) }
    }
    $global:CliMonConfig.FlatReportCsv.ColumnOrder = [Array]$local:columnOrderShadow2
    # Finally, time to try writing the report to the file.
    #  Write the flat report CSV to the output file and track the name in the global variable.
    $local:currentTime = (Get-Date -UFormat %Y-%m-%d-%H_%M).ToString()
    $global:CliMonFlatReportCsvName =
        ("{0}\FLAT-REPORT-{1}.csv" -f $global:CliMonConfig.ReportsDirectory, $local:currentTime)
    # First, write the Excel SEP=[delimiter] item. This helps Excel to automatically open the
    #  CSV without needing any special parameters set.
    try {
        Write-Output ("SEP=$($global:CliMonConfig.FlatReportCsv.Delimiter)") `
            | Out-File -FilePath $global:CliMonFlatReportCsvName
        # Now, append the rest of the CSV data after that first line; with ordered properties/columns
        #  based on the order given in the configuration.
        Write-Output ($local:flatReportContents `
            | Select-Object $global:CliMonConfig.FlatReportCsv.ColumnOrder `
            | ConvertTo-Csv -NoTypeInformation -Delimiter $global:CliMonConfig.FlatReportCsv.Delimiter) `
            | Out-File -Append -FilePath $global:CliMonFlatReportCsvName
        Write-Host "-- Flat Report written to: $($global:CliMonFlatReportCsvName)."
    } catch {
        Write-Host "~~ Failed to write CSV: $($global:CliMonFlatReportCsvName). Please check the ColumnOrder configuration." `
            -ForegroundColor Red
    }
}



##########################################
##########################################
##########################################
# The below functions are the work-horses.
# They will actually poll information from
#  the target clients.
##########################################

# Track filename patterns on the client machine.
# The client profile is adding this structure in this step:
# "FilenameTrackers" : {
#    UserProfilesCounts    : {  <user1>:{patterns-found}, ..., <userN>:{patterns-found}  }
#    CustomLocationsCounts : {  <loc1>:{patterns-found}, ..., <locN>:{patterns-found}  }
#    ProgramFilesCounts    : {  "ProgramFiles":{patterns-found}  }
#    SystemFilesCounts     : {  "SystemFiles":{patterns-found}  }
# }
#    ... where "patterns-found" uses the pattern from the patterns config variable as the key
#        and the count as the value.
#        There is also a "FILES_[pattern]" key for the actual full filenames found.
Function Get-ClientTrackedFiles() {
    param([Object]$TargetClient)
    Write-Host "---- Tracking filenames across specific target directories."
    # Harvest all target filenames that match the patterns defined in the configuration.
    [ScriptBlock]$local:doGetClientTrackedFiles = {
        # A helper function to cut out some of the repetition within inner layers.
        #  Sorts through DataInput (fed info from a Get-ChildItem call) and returns
        #  files that have matched a pattern, with their counts and names.
        Function Get-MatchingPatternsAndCounts() {
            param([Object[]]$DataInput, [String]$Profile = $null)
            $local:returnData = @{}
            # If the input isn't a valid array of objects, return an empty object.
            if($null -eq $DataInput -Or $DataInput.Length -eq 0) { return @{} }
            # For each filename pattern being checked (from the config), check every individual
            #  object in the contents of the input data. If a filename matches both the pattern,
            #  it will be tracked/reported in the return data.
            foreach($pattern in $global:CliMonConfig.FilenameTracking.Patterns.Keys) {
                Write-Debug -Message "Matching against pattern: $pattern" -Threshold 3 -Prefix '>>>>>>>>'
                # matchedFiles will store all files matching the pattern, depending on the call type.
                $local:matchedFiles =
                    if($Profile -ne $null -And $Profile -ne "") {
                        # If the Profile parameter is set, the iteration is complicated by
                        #  searching for BOTH a matching pattern and a matching profile.
                        $DataInput | Where-Object -Property FullName -Like "$($Profile)\*" `
                            | Where-Object -Property FullName -Match $pattern
                    } else {
                        # Otherwise, simply search for the pattern in the filenames.
                        ($DataInput | Where-Object -Property FullName -Match $pattern)
                    }
                # Strip the objects down to an array of all full file paths.
                $local:matchedFiles = $local:matchedFiles.FullName
                # fileCount will store the amount of files that matched the pattern.
                $local:fileCount = $local:matchedFiles.Count
                if($null -eq $local:fileCount) { $local:fileCount = 0 }   #prevent a null value
                Write-Debug -Message "Matched $($local:fileCount) files." -Threshold 3 -Prefix '>>>>>>>>'
                # Add the count onto the return data, as well as associated filenames for later.
                $local:returnData.Add($pattern, $local:fileCount)
                $local:returnData.Add("FILES_$($pattern)", ($local:matchedFiles `
                    | Select-Object -Last $global:CliMonConfig.FilenameTracking.ViewLimit))
            }
            # Send back the return data.
            return $local:returnData
        }

        # Empty return variable definition/declaration.
        $FilenameTrackingResults = @{}
        # Define the an empty hashtable: the final object added to the TrackedFiles location.
        $TrackedFiles = @{}

        # Check user directories, if enabled.
        if($global:CliMonConfig.FilenameTracking.Locations.UserProfiles -eq $True) {
            Write-Host "------ User Profiles."
            $local:UserProfileCounts = @{}
            # Get all directories in the default user path.
            $local:UserProfileDirectory = (Get-ItemProperty `
                'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\').ProfilesDirectory
            if($null -eq $UserProfileDirectory) {
                $UserProfileDirectory = $global:CliMonConfig.UserProfileBase
            }
            $local:UserProfiles = (Get-ChildItem -Path $UserProfileDirectory -Directory).FullName
            # Build an object in a single query that contains everything in each user profile.
            #  This is to prevent the script from needing to run this several times.
            $local:ProfileContents = $local:UserProfiles | ForEach-Object {
                Get-ChildItem -Path $_ -Recurse | Sort-Object CreationTime | Select-Object FullName
                if($? -eq $False) { <#Error getting directory contents#> }
            }
            # Go through each profile name.
            foreach($profile in $local:UserProfiles) {
                Write-Host "-------- $($profile)"
                # Make a call to the helper function to iterate each profile's match for the patterns.
                $local:UserProfileCounts.Add($profile, (Get-MatchingPatternsAndCounts `
                    -DataInput $local:ProfileContents -Profile $profile))
            }
            # Add the totals to the top-most scope of the object.
            $TrackedFiles.Add("UserProfilesCounts", $local:UserProfileCounts)
        } else { $TrackedFiles.Add("UserProfilesCounts", @{}) <# Add an empty table #> }

        # Check the $env:SystemRoot directory, if enabled.
        #  This should be used with extreme caution, as it could run the script out of memory!
        if($global:CliMonConfig.FilenameTracking.Locations.SystemFiles -eq $True) {
            Write-Host "------ The %SYSTEMROOT% directory (typically 'C:\Windows')"
            Write-Host "~~~~~~ WARNING: This could add a potentially-large delay per client."
            # Recursively get all files in the %SYSTEMROOT% location from the remote client.
            $local:SystemRootContents = Get-ChildItem -Path $env:SystemRoot -Recurse
            $local:SystemRootCounts = @{}
            # Add the results under the "SystemFiles" key. This gives the structure the same
            #  nesting as the UserProfiles section, despite it being only a single key. This is good.
            $local:SystemRootCounts.Add("SystemFiles", `
                (Get-MatchingPatternsAndCounts -DataInput $local:SystemRootContents))
            # Add to the final object.
            $TrackedFiles.Add("SystemFilesCounts", $local:SystemRootCounts)
        } else { $TrackedFiles.Add("SystemFilesCounts", @{}) <# Add an empty table #> }

        # Check the $env:ProgramData directory, if enabled.
        #  This should be used with caution as well: it too could cause a crash.
        if($global:CliMonConfig.FilenameTracking.Locations.ProgramData -eq $True) {
            Write-Host "------ The %PROGRAMDATA% directory (typically 'C:\ProgramData')"
            Write-Host "~~~~~~ WARNING: This could add a potentially-large delay in per-client processing."
            # Recurseively get all files in the %PROGRAMDATA% directory from the remote client.
            $local:ProgramDataContents = Get-ChildItem -Path $env:ProgramData -Recurse
            $local:ProgramDataCounts = @{}
            # Add the results under the "ProgramFiles" key.
            $local:ProgramDataCounts.Add("ProgramFiles", `
                (Get-MatchingPatternsAndCounts -DataInput $local:ProgramDataContents))
            # Add to the final object.
            $TrackedFiles.Add("ProgramFilesCounts", $local:ProgramDataCounts)
        } else { $TrackedFiles.Add("ProgramFilesCounts", @{}) <# Add an empty table #> }

        # Are there any custom directories? If so, get those too.
        #  This is a nice in-depth option for those that want to monitor very specific locations.
        if($global:CliMonConfig.FilenameTracking.CustomLocations.Keys.Count -gt 0) {
            Write-Host "------ Custom Directories:"
            # Define an intermediate object to hold each key/value pair of matching files per directory.
            $local:CustomDirTrackers = @{}
            # Iterate through each custom location, adding it to the "CustomDirTrackers" object.
            foreach($customLocation in $global:CliMonConfig.FilenameTracking.CustomLocations.Keys) {
                Write-Host "-------- '$($customlocation)'"
                $local:CustomDirContents =
                    if(-Not(Test-Path -Path $customLocation)) { $null } else {
                        # Recursion is dependent on what boolean value the config for the path returns.
                        Get-ChildItem -Path $customLocation `
                            -Recurse:$global:CliMonConfig.FilenameTracking.CustomLocations.$customLocation
                    }
                # Add the matching filenames to the intermediate object.
                $local:CustomDirTrackers.Add($customLocation, `
                    (Get-MatchingPatternsAndCounts -Profile $null -DataInput $local:CustomDirContents))
            }
            # Add the intermediate to the final object.
            $TrackedFiles.Add("CustomLocationsCounts", $local:CustomDirTrackers)
        } else { $TrackedFiles.Add("CustomLocationsCounts", @{}) }

        # Append the extracted information to the return object.
        $FilenameTrackingResults.Add("FilenameTrackers", $TrackedFiles)
        $FilenameTrackingResults.Add("FilenameTrackersPatterns", `
            ($global:CliMonConfig.FilenameTracking.Patterns.Keys | ForEach-Object { $_ }))
        # Return the finished object.
        return $FilenameTrackingResults
    }

    # Parse the results.
    $local:results = $TargetClient.RemoteCommand($local:doGetClientTrackedFiles, @($TargetClient))
    if($local:results.Success -eq $True) {
        # Success! Set the client's profile values accordingly.
        $TargetClient.Profile.FilenameTrackers =
            $local:results.Result.FilenameTrackers
        $TargetClient.Profile.FilenameTrackersPatterns =
            $local:results.Result.FilenameTrackersPatterns
    } else {
        # Failed to get the filenames in the target locations.
        Write-Host ("~~ [{0}] Failed to track filenames on the client machine." -f $TargetClient.Hostname)
    }
}

# Get all Profile information for the client in the five major categories:
#  InstalledApps, Services, StoreApps, StartupApps, ScheduledTasks
Function Get-ClientProfile() {
    param([Object]$TargetClient)
    # The below script block will harvest ALL target information from the client machine,
    #  with the exception of filename tracking. It return a Profile object.
    [ScriptBlock]$local:doGetClientProfile = {
        param([Object]$targetedClient)
        # Define a function within the session for extracting per-user information from the registry.
        Function Get-UserHiveContent() {
            param([Array]$registryTargets, [Boolean]$SepMembers = $False)
            Write-Debug -Message "Checking the user hives for requested information." -Threshold 1 -Prefix '>>>>'
            $registryTargets | ForEach-Object { Write-Debug -Message "TARGET LOCATION: $_" -Threshold 1 -Prefix '>>>>>>' }
            # Suppress all errors for this function.
            $priorELVL = $ErrorActionPreference; $ErrorActionPreference = 'SilentlyContinue'
            $allProfilesInfo = @{}
            # Iterate through each mounted hive to get the information therein from the targets.
            #  Thanks to the beauty of sessions, the $mountedHives value is still defined.
            #  This is among the "$Info" variable given earlier as well in Mount-UserHives.
            foreach($hive in $mountedHives) {
                Write-Debug -Message "Checking hive: $hive" -Threshold 2 -Prefix '>>>>>>'
                # Check whether the given hive name is a SID.
                if($hive -Match '^S-\d+-\d+-\d+-') {
                    Write-Debug -Message "The hive is interpreted as a SID type." -Threshold 3 -Prefix '>>>>>>>>'
                    # If so, translate the SID into a username, but continue using the SID for fetching data.
                    $userObj = New-Object System.Security.Principal.SecurityIdentifier("$hive")
                    $username = ($userObj.Translate([System.Security.Principal.NTAccount])).Value
                    $regLocation = $hive
                } else {
                    Write-Debug -Message "The hive is interpreted as a regular (non-SID) type." `
                        -Threshold 3 -Prefix '>>>>>>>>'
                    # Otherwise, set the username directly and use CLI-MON-[username] as the target.
                    $username = $hive
                    $regLocation = $hive -Replace "^$($global:CliMonConfig.DomainName)\\", "CLI-MON-"
                }
                # Now, go through each target given in the $registryTargets array.
                foreach($target in $registryTargets) {
                    # Dynamically replace [TARGET_USER] with the user's ID or mounted name.
                    $loc = $target -Replace '\[TARGET_USER\]', "$regLocation"
                    Write-Debug -Message "Scanning registry location: $loc" -Threshold 4 -Prefix '>>>>>>>>>>'
                    # Try to find the key/value pairs for the given location.
                    #  SepMembers will determine if the registry keys themselves return a value,
                    #  or if each is an individual object (and the PS* keys are desired instead).
                    if($SepMembers -eq $True) {
                        # Effectively returns all of the properties EXCEPT anything prefixed by PS*
                        $registryValue = Get-ItemProperty "$loc" | Get-Member -Type NoteProperty `
                            | Where-Object -Property Name -NotLike "PS*"
                    } else {
                        # Fetched directly.
                        $registryValue = Get-ItemProperty "$loc"
                    }
                    # TODO: A flaw with this is that when the registryTargets value is longer than just ONE
                    #       item, the script will spew a bunch of errors about the below Add operation due
                    #       to "duplicate key" presumably. This isn't an immediate concern, but it is for
                    #       future expansion, if more user-specific locations to be queried are discovered/added.
                    #
                    # Append the information onto the return variable for the user.
                    $allProfilesInfo.Add($username, $registryValue)
                }
            }
            
            # Return all collected information (and restore the ErrorActionPreference).
            $ErrorActionPreference = $priorELVL
            return $allProfilesInfo
        }
        
        # Define another function to notify of failures to get information.
        Function Show-InformationFailure() {
            param([String]$Category = "", [Int]$ID = $null)
            # Could potentially use the "ID" field later to notify of failure to get changes
            #  in the generated report, and just propagate the last successful report's changes.
            Write-Host (("~~~~ {0} couldn't be captured for this client at this time." + `
                " Please verify administrative permissions.") -f $Category)
        }

        # Set up the Profile object as a reference to the target client's profile.
        $Profile = $targetedClient.Profile

        # BEGIN INFORMATION COLLECTION:
        # 
        # The below blocks are labeled according to the information they gather.
        #  As the comment on the first block states: though pointless, the "if true"
        #  scoping makes for easier code navigation during such complex operations.
        #
        # A special NOTE for final hashtables returned by the below five sections:
        #  The CSV formatting conversions are placed to force enum results to always
        #  output the String object representation of the data. This is extremely
        #  important for the script to properly store and compare reports.

        # -----------------------------------------
        # Collect installed applications.
        if($True) {   #scoping for ease of collapse
            Write-Host "---- Gathering installed applications..."
            $installedAppsIntermediate = @{}
            Write-Debug -Message "Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" `
                -Threshold 1 -Prefix '>>>>'
            $installedAppsIntermediate.Add("HKLM", `
                (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*))
            Write-Debug -Message "Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" `
                -Threshold 1 -Prefix '>>>>'
            $installedAppsIntermediate.Add("6432Node", `
                (Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*))
            $installedAppsTargets = @(
                "REGISTRY::HKEY_USERS\[TARGET_USER]\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
            )
            $perProfileInstalledApps = Get-UserHiveContent `
                -registryTargets $installedAppsTargets -SepMembers $False 
            $installedAppsIntermediate += $perProfileInstalledApps
            # Build an index and hashtable.
            $installedApps = @{}; $installedAppsIndex = @()
            Write-Debug -Message "Indexing and building the final report object." -Threshold 2 -Prefix '>>>>'
            foreach($appKey in $installedAppsIntermediate.Keys) {
                Write-Debug -Message "Examining InstalledApps key TYPE: $appKey" -Threshold 2 -Prefix '>>>>>>'
                foreach($app in $installedAppsIntermediate.$appKey) {
                    if($null -eq $app) { continue }
                    # Define the index key, and add it to the index.
                    $keyname = "$($app.PSChildName)_$appKey"
                    Write-Debug -Message "Created InstalledApps keyname: $keyname" -Threshold 2 -Prefix '>>>>>>>>'
                    $installedAppsIndex += $keyname
                    # Create a new hashtable using the keyname as... the key.
                    $installedApps.Add($keyname, `
                        ($installedAppsIntermediate.$appKey `
                            | Where-Object -Property PSPath -eq "$($app.PSPath)" `
                            | Select-Object $global:CliMonConfig.TrackedValues.InstalledApps `
                            | ConvertTo-Csv | ConvertFrom-Csv `
                        ) `
                    )
                }
            }
            # Add it to the profile.
            $Profile.InstalledApps = $installedApps
            $Profile.InstalledAppsIndex = $installedAppsIndex
        }

        # -----------------------------------------
        # Harvest Windows Store-based applications.
        if($True) {
            Write-Host "---- Gathering store applications..."
            # Extract a list of store applications for all users on the machine.
            Write-Debug -Message "Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue" -Threshold 1 -Prefix '>>>>'
            try {
                $storeAppsIntermediate = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            } catch { Show-InformationFailure -Category "Store apps" -ID 2 }
            # Loop over each package returned in the store.
            #  These are keyed based on their PackageFullName property values.
            $storeApps = @{}; $storeAppsIndex = @()
            Write-Debug -Message "Indexing and building the final report object." -Threshold 2 -Prefix '>>>>'
            foreach($app in $storeAppsIntermediate) {
                $keyname = "$($app.PackageFullName)"
                # Prevent any duplicate key names by appending an underscore when dupes are detected.
                # TODO: This is unreliable (and maybe unnecessary) because the order 
                #        of these might change with each run of the script.
                for($i = 0; $i -lt 4; $i++) {
                    if($storeApps.ContainsKey($keyname)) { $keyname += "_" }
                }
                Write-Debug -Message "Created StoreApps key: $keyname" -Threshold 2 -Prefix '>>>>>>'
                # Get all the fields from the StoreApps trackers that are requested in the configuration.
                $storeAppInfo = ($storeAppsIntermediate `
                    | Where-Object -Property PackageFullName -eq "$($app.PackageFullName)" `
                    | Select-Object $global:CliMonConfig.TrackedValues.StoreApps `
                    | ConvertTo-Csv | ConvertFrom-Csv)
                # Additionally, ALWAYS track the PackageUserInformation to find 
                #  out who has which apps, and their statuses.
                $perUserAppStatus = "App Status: `r`n" + [System.String]::Join("`r`n", `
                    @(($storeAppsIntermediate `
                        | Where-Object -Property PackageFullName -eq "$($app.PackageFullName)").PackageUserInformation `
                        | ForEach-Object {
                            ($_ | Select-String -Pattern '\[[\\\w]+\]\s*\:\s+\w+' -AllMatches).Matches.Value
                        }
                    )
                )
                Write-Debug -Message "Splicing PackageUserInformation: $perUserAppStatus" -Threshold 4 -Prefix '>>>>>>'
                # Add the PackageUserInformation property (with the extractions) into the final object.
                $storeAppInfo | Add-Member -Name PackageUserInformation `
                    -Type NoteProperty -Value "$($perUserAppStatus)"
                # Finally append it all to the keyname (and index).
                $storeApps.Add($keyname, $storeAppInfo)
                $storeAppsIndex += $keyname
            }
            # Add the results to the client profile.
            $Profile.StoreApps = $storeApps
            $Profile.StoreAppsIndex = $storeAppsIndex
        }

        # -----------------------------------------
	    # Harvest startup applications.
        if($True) {
            Write-Host "---- Gathering startup applications..."
            $startupAppsTargets = @(
                "REGISTRY::HKEY_USERS\[TARGET_USER]\Software\Microsoft\Windows\CurrentVersion\Run\"
            )
            # Get the per-profile startup apps from the registry key(s) above.
            $perProfileStartupApps = Get-UserHiveContent `
                -registryTargets $startupAppsTargets -SepMembers $True
            $startupApps = @{}; $startupAppsIndex = @()
            # For every user in the mounted registry point, parse the returned information.
            foreach($user in ($perProfileStartupApps.Keys | Sort-Object)) {
                Write-Debug -Message "Examining user startup apps for: $user" -Threshold 2 -Prefix '>>>>'
                foreach($item in $perProfileStartupApps.$user) {
                    if($null -eq $item) { continue }
                    $keyname = "$($item.Name)_$($user)"
                    Write-Debug -Message "Created keyname: $keyname" -Threshold 3 -Prefix '>>>>>>'
                    $addedInformation = [Ordered]@{}
                    # Set special property values on the object based on which configuration values are tracked.
                    foreach($value in $global:CliMonConfig.TrackedValues.StartupApps) {
                        if($value -eq "Command") {
                            $addedInformation.Add($value, "$($item.Definition -Replace 'string ')")
                        } elseif($value -eq "Location") {
                            $userNoDomain = $user -Replace "^$($global:CliMonConfig.DomainName)\\"
                            $addedInformation.Add($value, "HKEY_USERS\$($userNoDomain)")
                        } elseif($value -eq "User") {
                            $addedInformation.Add($value, "$($user)")
                        } else { $addedInformation.Add($value, "") }
                    }
                    $startupApps.Add($keyname, $addedInformation)
                    $startupAppsIndex += $keyname
                }
            }
            # Collect and aggregate more startup commands from CIM.
            Write-Debug -Threshold 1 -Prefix '>>>>' -Message ("Get-CimInstance Win32_StartupCommand " +
                "| Where-Object -Property User -Match `"^(Public|NT\sAUTHORITY\\.+)$`"")
            $startupCommandsW32 = Get-CimInstance Win32_StartupCommand `
                | Where-Object -Property User -Match "^(Public|NT\sAUTHORITY\\.+)$"
            foreach($startupapp in $startupCommandsW32) {
                $keyname = "$($startupapp.Name)_$($startupapp.User)"
                Write-Debug -Message "Creating StartupApps key: $keyname" -Threshold 2 -Prefix '>>>>>>'
                $startupApps.Add($keyname, `
                    ($startupCommandsW32 `
                        | Where-Object -Property Name -eq "$($startupapp.Name)" `
                        | Where-Object -Property User -eq "$($startupapp.User)" `
                        | Select-Object $global:CliMonConfig.TrackedValues.StartupApps `
                    ) `
                )
                $startupAppsIndex += $keyname
            }

            # Collect and aggregate even more from the "6432Node" registry location.
            Write-Debug -Threshold 1 -Prefix '>>>>' `
                -Message "(Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run) ``"
            Write-Debug -Threshold 1 -Prefix '>>>>' `
                -Message "    | Get-Member -Type NoteProperty | Where-Object -Property Name -NotLike `"PS*`""
            $6432NodeItems = `
                (Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run) `
			    | Get-Member -Type NoteProperty | Where-Object -Property Name -NotLike "PS*"
            foreach($item in $6432NodeItems) {
                $keyname = "$($item.Name)_6432Node"
                Write-Debug -Message "Creating StartupApps keyname: $keyname" -Threshold 2 -Prefix '>>>>>>'
                $addedInformation = @{}
                # Set special property values on the object based on which configuration values are tracked.
                foreach($value in $global:CliMonConfig.TrackedValues.StartupApps) {
                    if($value -eq "Command") {
                        $addedInformation.Add($value, "$($item.Definition -Replace 'string ')")
                    } elseif($value -eq "Location") {
                        $addedInformation.Add($value, "64-to-32_Registry_Node")
                    } elseif($value -eq "User") {
                        $addedInformation.Add($value, "6432Node")
                    } else { $addedInformation.Add($value, "") }
                }
                $startupApps.Add($keyname, $addedInformation)
                $startupAppsIndex += $keyname
            }

            # Add the final information to the client profile.
            $Profile.StartupApps = $startupApps
            $Profile.StartupAppsIndex = $startupAppsIndex
        }

        # -----------------------------------------
        # Get services.
        if($True) {
            Write-Host "---- Gathering services..."
            # Use the Get-Service command to collect a list of services.
            Write-Debug -Message "Get-Service" -Threshold 1 -Prefix '>>>>'
            $servicesIntermediate = Get-Service
            $services = @{}; $servicesIndex = @()
            # Iterate over them and create the index and unique hashtable objects.
            foreach($service in $servicesIntermediate) {
                $keyname = "$($service.DisplayName)_$($service.Name)"
                Write-Debug -Message "Creating Services keyname: $keyname" -Threshold 2 -Prefix '>>>>>>'
                $services.Add($keyname, `
                    ($servicesIntermediate `
                        | Where-Object -Property DisplayName -eq "$($service.DisplayName)" `
                        | Select-Object $global:CliMonConfig.TrackedValues.Services `
                        | ConvertTo-Csv | ConvertFrom-Csv `
                    ) `
                )
                $servicesIndex += $keyname
            }
            # Add the final information to the client profile.
            $Profile.Services = $services
            $Profile.ServicesIndex = $servicesIndex
        }

        # -----------------------------------------
	    # Get scheduled tasks and jobs.
        if($True) {
            Write-Host "---- Gathering scheduled tasks..."
            # Use the Get-ScheduledTask function to get a list of tasks.
            Write-Debug -Message "Get-ScheduledTask" -Threshold 1 -Prefix '>>>>'
            $scheduledTasksIntermediate = Get-ScheduledTask
            $scheduledTasks = @{}; $scheduledTasksIndex = @()
            # Iterate through each and build the profile objects.
            foreach($task in $scheduledTasksIntermediate) {
                $keyname = "$($task.URI)"
                Write-Debug -Message "Creating ScheduledTask keyname: $keyname" -Threshold 2 -Prefix '>>>>>>'
                $scheduledTasks.Add($keyname, `
                    ($scheduledTasksIntermediate `
                        | Where-Object -Property URI -eq "$($task.URI)" `
                        | Select-Object $global:CliMonConfig.TrackedValues.ScheduledTasks `
                        | ConvertTo-Csv | ConvertFrom-Csv `
                    ) `
                )
                $scheduledTasksIndex += $keyname
            }
            # Add the information to the client profile.
            $Profile.ScheduledTasks = $scheduledTasks
            $Profile.ScheduledTasksIndex = $scheduledTasksIndex
        }

        # Return the completed profile.
        return [Hashtable]$Profile
    }

    # Parse the results.
    $local:results = $TargetClient.RemoteCommand($local:doGetClientProfile, @($TargetClient))
    if($local:results.Success -eq $True) {
        # Success! Set the client's profile to the harvested profile.
        $TargetClient.Profile = $local:results.Result
    } else {
        # Failed to get the information, for whatever reason. Do something here.
        #  Something useful would be to just propagate the previous profile's results forward,
        #  but this might be exploitable.
        Write-Host ("~~ [{0}] Could not get the client's profile information." -f $TargetClient.Hostname)
    }
}
