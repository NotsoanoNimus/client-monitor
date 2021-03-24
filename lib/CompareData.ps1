<#
 # CompareData.ps1
 #
 # Methods regarding the collection of report differences (i.e. "deltas") for use in the
 #  final notification. This step intentionally does NOT include the data filtering or
 #  suppression that the final notification generation stage does. This is so that a full
 #  delta report (unfiltered) can still be read and digested as desired, or if needed.
 #>



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



# Define a template object used to track all changes from one report to the next.
#  Any differences between the prior report and the most recent report will be tracked here.
$global:CliMonEmptyDeltas = [Ordered]@{
    NewServices = @{}; RemovedServices = @{};	ChangedServices = @{}
    NewInstalledApps = @{}; RemovedInstalledApps = @{}; ChangedInstalledApps = @{}
    NewStoreApps = @{}; RemovedStoreApps = @{}; ChangedStoreApps = @{}
    NewStartupApps = @{}; RemovedStartupApps = @{}; ChangedStartupApps = @{}
    NewScheduledTasks = @{}; RemovedScheduledTasks = @{}; ChangedScheduledTasks = @{}
    FilenameViolations = @{}; MatchedSubnets = $null;
}

# Called from the main method. Populate the final "CliMonDeltas" object with the differences
#  between client machines, indexed on a per-machine basis.
Function Compare-EnvironmentDeltas() {
    Write-Host "`n`n`nComparing the differences between current reports and prior reports." `
        -ForegroundColor Green
    # This is a preparatory step, to forcibly cause a comparison between a property that is not
    #  intended to be manually removable by a user of this script.
    $global:CliMonConfig.TrackedValues.StoreApps += "PackageUserInformation"
    # Check if the automatic tracking/filtering of version changes is enabled.
    #  If so, get the current list of applications that are pre-filtered and store it in a global value.
    if($global:CliMonConfig.Notifications.InstallationChanges.Enabled -eq $True) {
        # Declared in this scope (just in case).
        $local:readInApplicationFilters = @{}
        try {
            Write-Debug -Message "Getting automatic installation changes tracking information" `
                -Threshold 1 -Prefix '>>>>'
            $local:readInApplicationFilters = Get-InstalledAppsTrackerContents
        } catch {
            $local:readInApplicationFilters = (@{} | ConvertTo-Json)
            Write-Host ("~~~~ Automatic application tracking is enabled but the ReportLocation" +
                " couldn't be read. No applications will be tracked.")
        }
        # Set the value of the global tracker for installed application updates to a "snapshot" of the
        #  filters BEFORE they're updated at all. This allows things that are detected on this run to 
        #  be included in the report still (but then suppresses them in future reports).
        $global:CliMonUpdatedApplicationTrackingFilters = $local:readInApplicationFilters
    }
    # Set up scaffolding for the deltas object. It will be a hashtable of per-client-hostname
    #  difference objects, as defined in the below loop.
    $global:CliMonDeltas = @{}
    foreach($client in $global:CliMonClients) {
        # Set a localized tracker equal to a copy of the global deltas variable.
        $deltasObject = [Ordered]@{
            NewServices = @{}; RemovedServices = @{};	ChangedServices = @{}
            NewInstalledApps = @{}; RemovedInstalledApps = @{}; ChangedInstalledApps = @{}
            NewStoreApps = @{}; RemovedStoreApps = @{}; ChangedStoreApps = @{}
            NewStartupApps = @{}; RemovedStartupApps = @{}; ChangedStartupApps = @{}
            NewScheduledTasks = @{}; RemovedScheduledTasks = @{}; ChangedScheduledTasks = @{}
            FilenameViolations = @{}; MatchedSubnets = $null;
			LocalAdmins = @();
        }
        # Collect the top of the list for most recent files/reports matching the given hostname.
        #  Any $null return from this function indicates failure to retrieve the report.
        $mostRecentReport = Get-ClientReport -TargetClient $client
        # If SnapshotMode is enabled, set the reference/prior object to $null.
        $priorReport = 
            if($SnapshotMode -eq $False) {
                Get-ClientReport -TargetClient $client -IsPrior
            } else { $null }
        # If an object isn't returned from the query below, assume there is no "prior" report.
        if($null -eq $priorReport) {
            # If the prior report is empty, initialize a blank version of a client profile.
            $priorReport = @{}
        }
        # Call another wrapper method that contains all processing for differences between the prior
        #  report and the most recent/current report. This will modify the reference to $deltasObject.
        # NOTE: This is only done if the client is both online and invokable.
        if($client.Profile.IsOnline -eq $True -And $client.Profile.IsInvokable -eq $True) {
            Get-ClientDeltas -ClientDeltasRef $deltasObject `
                -MostRecentReport $mostRecentReport -PriorReport $priorReport
        }
        # Add on the online/invokable status changes to the deltas object. This will be used for
        #  both the DeltasReport (if enabled) and the notifications section.
        $deltasObject.Add("OnlineStatusChange", $client.Profile.OnlineStatusChange)
        $deltasObject.Add("InvokableStatusChange", $client.Profile.InvokableStatusChange)
        # If enabled, check the client's IP address(es) against the list of 'alert' subnets.
        #  Populates the "MatchedSubnets" property of the Deltas reference object.
        if($global:CliMonConfig.Notifications.IpAddressAlerts.Enabled -eq $True) {
            $deltasObject.MatchedSubnets =
                Get-IpAddressAlertSubnets -TargetClient $client
        }
		# If enabled, check for any disallowed local administrators on the client.
		$local:badAccts = $False
		if($global:CliMonConfig.Notifications.LocalAdminTracking.Enabled -eq $True -And `
		  $null -ne $client.Profile.LocalAdmins) {
			# Test each account name against possible config-based exceptions, and trigger if one's found.
			[System.Collections.ArrayList]$local:keptAccts = $client.Profile.LocalAdmins.Clone()
			if($null -ne $global:CliMonConfig.Notifications.LocalAdminTracking.PerClientExceptions[$client.Hostname]) {
				$local:t = $global:CliMonConfig.Notifications.LocalAdminTracking.PerClientExceptions[$client.Hostname]
				#[System.Collections.ArrayList]$local:keptAccts = $client.Profile.LocalAdmins.Clone()
				foreach($account in $client.Profile.LocalAdmins) {
					if($null -eq $account -Or $account -eq "") { $local:keptAccts.Remove($account); }
					elseif($account -inotmatch $local:t) {
						# There a non-excepted account, trigger the alarm for the client and DON'T remove the item.
						$local:badAccts = $True
					} else {
						# Anything with a per-client exception needs to be removed from the array.
						$local:keptAccts.Remove($account)
					}
				}
			} else {
				# Still clean null entries.
				foreach($account in $client.Profile.LocalAdmins) {
					if($null -eq $account -Or $account -eq "") { $local:keptAccts.Remove($account); }
				}
				# All accounts are considered bad if there are no exceptions for this client (and some remain after the null-check).
				if($local:keptAccts.Count -gt 0) { $local:badAccts = $True; }
			}
			# Assign the resulting array back to the profile.
			$local:deltasObject.LocalAdmins = $local:keptAccts.ToArray()
			if($local:deltasObject.LocalAdmins.Count -gt 0) {
				Write-Host "----" -NoNewline
				Write-Host " Detected disallowed local administrators on this client." -ForegroundColor Magenta
			}
		}
        # Set up a "sensor" variable to detect if the sub-keys within each Key in the deltas tables
        #  are different in quantity across any of the property types. If a difference is detected
        #  in the number of sub-keys for any one of the properties, the client had some kind of
        #  change tracked in the above methods. $detectDeltas is a boolean array.
        $local:detectDeltas = $global:CliMonEmptyDeltas.Keys | ForEach-Object {
            $global:CliMonEmptyDeltas[$_].Count -eq $deltasObject[$_].Count
        }
        # If the boolean array contains a False (meaning non-equivalence) or if the client had some
        #  kind of important change, then add the client's changes to the CliMonDeltas tracker.
        if(
            $local:detectDeltas.Contains($False) -Or
            $deltasObject.OnlineStatusChange -eq $True -Or
            $deltasObject.InvokableStatusChange -eq $True -Or
			$local:badAccts -eq $True
        ) {
            # Add the deltasObject to the global tracking hashtable, indexed by client hostname.
            Write-Host "---- Changes or alerts were detected for this client. Tracking." -ForegroundColor Yellow
            $global:CliMonDeltas.Add($client.Hostname, $deltasObject)
        }
    }
    # If the $DeltasReport switch is set to True, then generate the deltas report in the
    #  ReportsDirectory location for the user to read through as an 'unfiltered' JSON view
    #  of all client changes in the environment.
    # ~~~~~~NOTE: If "snapshot" mode is enabled, no deltas are being measured (and no reports are
    #  being written) so there is nothing to output.~~~~~~
    # The above note is invalid: if the -DeltasReport flag is set, then generate the report like
    #  the user wants. No need to invalidate that switch if Snapshot Mode is enabled.
    if($DeltasReport -eq $True -And $global:CliMonDeltas.Count -gt 0) {
        # Get a formatted version of the current time.
        $local:currentTime = (Get-Date -UFormat %Y-%m-%d-%H_%M).ToString()
        $global:CliMonDeltasReportName =
            ("{0}\DELTAS-{1}.txt" -f $global:CliMonConfig.ReportsDirectory, $local:currentTime)
        # Output the deltas in JSON format to the DELTAS-{time}.txt file in the ReportsDirectory.
        Write-Output ($global:CliMonDeltas | ConvertTo-Json -Depth 6 `
            -Compress:$global:CliMonConfig.DeltasReport.Compressed) `
            | Out-File -FilePath $global:CliMonDeltasReportName
        Write-Host "`n`n`nDeltas written to $($global:CliMonDeltasReportName)." `
            -ForegroundColor Yellow
    } elseif($global:CliMonDeltas.Count -le 0) {
        # Notify the user that there weren't any changes detected across the clients.
        Write-Host "`n`n`nNo changes were detected within the client environment." `
            -ForegroundColor Yellow
    }
    # Set the global flag to indicate whether or not changes were found.
    #  This serves to notify the notifications section of the script.
    $global:CliMonNoDeltas = ($global:CliMonDeltas.Count -le 0)
}



# A wrapper method for getting the deltas for each category. Uses the referenced deltasObject to
#  populate information and changes it discovers.
Function Get-ClientDeltas() {
    param(
        [Object]$ClientDeltasRef,
        [Object]$MostRecentReport,
        [Object]$PriorReport
    )
    # Iterate each key in the "TrackedValues" hashtable from the configuration.
    #  The keys array looks something like: @("InstalledApps", "StoreApps", ...)
    foreach($propertySet in $global:CliMonConfig.TrackedValues.Keys) {
        # For each property set in the "TrackedValues" configuration table, select certain
        #  sub-tables within the referenced deltas object and populate them according
        #  to changes that have been detected between the Current/Prior comparison,
        #  where "Prior" is the report from the last run of the script and "Current" is the
        #  report generated most recently during the current run of the script.
        # This function doesn't return a value, as it's just modifying the reference.
        Write-Host "---- Comparing property set: $propertySet"
        Compare-ClientDeltas `
            -CompareProperties $global:CliMonConfig.TrackedValues.$propertySet `
            -DeltasObjChanged $ClientDeltasRef."Changed$($propertySet)" `
            -DeltasObjNew $ClientDeltasRef."New$($propertySet)" `
            -DeltasObjRemoved $ClientDeltasRef."Removed$($propertySet)" `
            -Current $MostRecentReport.$propertySet `
            -CurrentIndex $MostRecentReport."$($propertySet)Index" `
            -Prior $PriorReport.$propertySet `
            -PriorIndex $PriorReport."$($propertySet)Index"
    }
    # Track filename violations as well. These are entirely separate and much more complicated.
    #  This function actually returns an object of the differences instead of using a reference.
    Write-Host "---- Searching for tracked filename patterns exceeding their thresholds..."
    $ClientDeltasRef.FilenameViolations =
        Compare-ClientFiles -Prior $PriorReport -Current $MostRecentReport
}

# Compare client deltas in the selected category, between the "Current" and "Prior" profile
#  objects that have been imported.
Function Compare-ClientDeltas() {
    param(
        [Array]$CompareProperties,
        [Object]$DeltasObjChanged,
		[Object]$DeltasObjNew,
		[Object]$DeltasObjRemoved,
		[Object]$Current,
		[Object]$CurrentIndex,
		[Object]$Prior,
		[Object]$PriorIndex
    )
    # Go through each item in the index for the Current selection and get the deltas.
    Write-Debug -Message "Iterating through CURRENT keys to search for differences." -Threshold 2 -Prefix '>>>>'
    foreach($item in $CurrentIndex) {
        Write-Debug -Message "Examining CURRENT item key: $item" -Threshold 3 -Prefix '>>>>>>'
        # Using the index item as a shared key, get the corresponding value from each object.
        $currentObject = $Current.$item
        $priorObject = $Prior.$item
        # If a hashtable isn't found in the Prior object, assume the Current item is new.
        #  The actual processing for that is handled in the next loop.
        if($null -eq $priorObject -Or @{} -eq $priorObject) {
            Write-Debug -Message "The prior object is null; this must be a new key." -Threshold 3 -Prefix '>>>>>>>>'
            continue
        }
        # Compare properties between the two report objects and return it as an array of True/False.
        $local:diffs = $CompareProperties `
            | ForEach-Object { $currentObject.$_ -ne $priorObject.$_ }
        # If a "True" value was found, then there was a difference detected.
        if($local:diffs.Contains($True)) {
            Write-Debug -Message "A change between the two objects with this key was detected." `
                -Threshold 3 -Prefix '>>>>>>>>'
            # If auto-tracking is enabled and this is a Compare-ClientDeltas for InstalledApps...
            if(($global:CliMonConfig.Notifications.InstallationChanges.Automatic -eq $True) -And
              (Test-Path $global:CliMonConfig.Notifications.InstallationChanges.ReportLocation) -And
              $CompareProperties.Contains("DisplayName") -And
              $CompareProperties.Contains("DisplayVersion")) {
                # ... check that the versions are different. This is required to mark a change.
                if($currentObject."DisplayVersion" -ne $priorObject."DisplayVersion") {
                    Write-Debug -Message "Version change in InstalledApp detected." -Threshold 4 -Prefix '>>>>>>>>>>'
					Write-Debug -Message "CURRENT INFORMATION:`n$($currentObject | Format-List | Out-String)" -Threshold 4 -Prefix '>>>>>>>>>>>>'
					Write-Debug -Message "PRIOR INFORMATION:`n$($currentObject | Format-List | Out-String)" -Threshold 4 -Prefix '>>>>>>>>>>>>'
					if([String]::IsNullOrEmpty($currentObject.DisplayName) -ne $True -And
					  [String]::IsNullOrEmpty($currentObject.DisplayVersion) -ne $True) {
						# Get the current properties for the application with the given display name.
						$local:installedAppFilterProperties =
							$global:CliMonUpdatedApplicationTrackingFilters."$($currentObject.DisplayName)"
						# Check to ensure that the display version isn't already tracked/marked.
						if($local:installedAppFilterProperties -INotContains "$($currentObject.DisplayVersion)") {
							Write-Debug -Message ("{App '$($currentObject.DisplayName)', Version " +
								"'$($currentObject.DisplayVersion)'} added to the tracker.") `
								-Threshold 4 -Prefix '>>>>>>>>>>'
							# Add the display version to the tracker for this application.
							$local:installedAppFilterProperties += @($currentObject.DisplayVersion)
							# Splice the application back onto the object.
							$global:CliMonUpdatedApplicationTrackingFilters `
								| Add-Member -Name "$($currentObject.DisplayName)" `
								-Value $local:installedAppFilterProperties -Type NoteProperty -Force
							# Set the flag to True that some changes were added.
							$global:CliMonAutoTrackingIndexChanged = $True
						}
                    } else {
						Write-Debug -Message "SKIPPING. The name or version field is EMPTY!" -Threshold 3 -Prefix '>>>>>>>>>>'
					}
                }
            }
            # For each property to compare, add the _prior label with the value of the Prior object.
            #  This effectively forces the "Current" profile to become a combination of itself and
            #  the prior object as well.
            Write-Debug -Message "Splicing the '_prior' properties onto the Current object." `
                -Threshold 3 -Prefix '>>>>'
            $CompareProperties | ForEach-Object {
                $currentObject | Add-Member -Name "$($_)_prior" `
                    -Value $priorObject.$_ -Type NoteProperty
            }
            # Add it to the object pointer for the Changed value.
            $DeltasObjChanged.Add("$($item)", $currentObject)
        }
    }
    # Compare the indices of fields to see if an application was added or removed.
    if($null -eq $CurrentIndex) { $CurrentIndex = @() }
    if($null -eq $PriorIndex) { $PriorIndex = @() }
    Write-Debug -Message "Comparing object indices to determine new/removed items." -Threshold 2 -Prefix '>>>>'
    $local:indexDiffs = Compare-Object $CurrentIndex $PriorIndex
    foreach($difference in $local:indexDiffs) {
        $local:diff = $difference.InputObject
        if($difference.SideIndicator -eq "<=") {
            # The item was added.
            Write-Debug -Message "New item: $($local:diff)" -Threshold 3 -Prefix '>>>>>>'
            $DeltasObjNew.Add("$($local:diff)", $Current.$local:diff)
        } elseif($difference.SideIndicator -eq "=>") {
            # The item was removed.
            Write-Debug -Message "Removed item: $($local:diff)" -Threshold 3 -Prefix '>>>>>>'
            $DeltasObjRemoved.Add("$($local:diff)", $Prior.$local:diff)
        }
    }
}

# A helper function that attempts to read the contents of the installation changes tracker file
#  and returns a converted value if the conversion is possible, and an empty object if not.
Function Get-InstalledAppsTrackerContents() {
    $local:prefilterTrackers = (@{} | ConvertTo-Json)
    if(Test-Path "$($global:CliMonConfig.Notifications.InstallationChanges.ReportLocation)") {
        # Read in the current filters that have been automatically tracked.
        #  The location is configured in the configuration node below.
        $local:prefilterTrackers = 
            Get-Content $global:CliMonConfig.Notifications.InstallationChanges.ReportLocation `
            | ConvertFrom-Json
        # If the above wasn't successful, revert the value to an empty JSON object again.
        if($? -eq $False) { throw } else {
            Write-Debug -Message "The tracker file exists and was extracted." -Threshold 2 -Prefix '>>>>>>'
        }
    }
    return $local:prefilterTrackers
}

# Compare client file differences between Prior and Current reports. Filename tracking
#  comparisons are for DIFFERENCES only, and will not simply add a "count" to the generated
#  notification that tells a user how many files are in a location, unless the given threshold
#  is passed BETWEEN TWO REPORTS.
# If categories are added or removed (e.g. when SystemFiles tracking is (dis/en)abled),
#  they will NOT appear on the next report as a count of "lost" files or "gained" files.
#  This is due to the way that filename tracking works by measuring against a threshold.
#  When a new location is enabled or added, the script is smart enough to know that the
#  reference value would be zero and a "threshold" is an invalid measurement for that run.
#  Thus, if a user of the script wants to enable a location and get the count of files in
#  the next run, they should simply check the report generated for that run.
Function Compare-ClientFiles() {
    param([Object]$Prior, [Object]$Current)
    # Set two variables equal to the content of the tracked filenames from the reports.
    $currentFilenames = $Current.FilenameTrackers
    $priorFilenames = $Prior.FilenameTrackers
    # Structure of these nested loops:
	#    $category = "Outer" nest (like "SystemFilesCounts"). Equal to the LOCATION of the tracking.
	#    $subcategory = Per-user/Per-location information (like "C:\Users\TestAccount").
    #    $pattern = The pattern or FILES_ key in the actual hashtable.
    # The filename deltas object will hold all finalized differences between the two reports.
    $filenameDeltas = @{}
    # For each category in the fields/properties at the highest level of the filename trackers...
    foreach($category in ($currentFilenames | Get-Member -Type NoteProperty).Name) {
        Write-Debug -Message "Examining category: $category" -Threshold 1 -Prefix '>>>>'
        $categoryDeltas = @{}
        # ... go through each location, and then...
        foreach($subcategory in ($currentFilenames.$category | Get-Member -Type NoteProperty).Name) {
            Write-Debug -Message "Examining subcategory: $subcategory" -Threshold 2 -Prefix '>>>>>>'
            $subcategoryDeltas = @{}
            # ... go through each pattern:
            foreach($pattern in $Current.FilenameTrackersPatterns) {
                Write-Debug -Message "Examining pattern: $pattern" -Threshold 3 -Prefix '>>>>>>>>'
                # If the previous object at the current pattern is null/empty, this might be a new
                #  key; move on as there are no deltas to measure.
                if($null -eq $priorFilenames.$category.$subcategory.$pattern -Or
                  $priorFilenames.$category.$subcategory.$pattern -eq @{}) { continue }
                # Get the threshold for the pattern from the configuration.
                $itemThreshold = $global:CliMonConfig.FilenameTracking.Patterns.$pattern
                Write-Debug -Message "Configured pattern threshold: $itemThreshold" -Threshold 4 -Prefix '>>>>>>>>>>'
                # If the threshold is set to 0 (or less), or isn't an integer, set it to a very high
                #  value to guarantee that it won't matter (which invalidates the threshold purposely).
                if($itemThreshold -le 0 -Or $itemThreshold -IsNot 'Int32') { $itemThreshold = 999999 }
                # Get the difference between the file counts matching the given pattern between reports.
                $filenameCountDelta = ($currentFilenames.$category.$subcategory.$pattern `
                    - $priorFilenames.$category.$subcategory.$pattern)
                # If the difference from the current report to the prior report exceeds the threshold...
                if($filenameCountDelta -ge $itemThreshold) {
                    Write-Debug -Message "Pattern '$pattern' has exceeded the configured threshold." `
                        -Threshold 3 -Prefix '>>>>>>>>'
                    # ... add the new count and the previous counts to the deltas tracking object.
                    #  Also, add the filenames and the threshold value for added information.
                    # This constructs a lowest-scope structure of:
                    #   $pattern            : The Current count matching the $pattern.
                    #   Files_$pattern      : The list of files from the current object.
                    #   Threshold_$pattern  : The threshold that was exceeded.
                    #   __Prior_$pattern    : The Prior count matching the $pattern.
                    $subcategoryDeltas.Add($pattern, $currentFilenames.$category.$subcategory.$pattern)
                    $subcategoryDeltas.Add("Files_$($pattern)", `
                        $currentFilenames.$category.$subcategory."Files_$($pattern)")
                    $subcategoryDeltas.Add("Threshold_$($pattern)", $itemThreshold)
                    $subcategoryDeltas.Add("__Prior_$($pattern)", `
                        $priorFilenames.$category.$subcategory.$pattern)
                }
            }
            # Was anything added to the subcategoryDeltas based on the threshold for the pattern?
            if($subcategoryDeltas.Keys.Count -gt 0) {
                # If so, add the subcategory deltas to the per-category deltas.
                $categoryDeltas.Add($subcategory, $subcategoryDeltas)
            }
        }
        # Is there anything added to the categoryDeltas object?
        if($categoryDeltas.Keys.Count -gt 0) {
            # If so, add the category deltas onto the final object.
            $filenameDeltas.Add($category, $categoryDeltas)
        }
    }
    # Once the loops complete, examine the filenameDeltas object.
    if($filenameDeltas.Keys.Count -gt 0) {
        # If changes were detected, return the threshold violations to the deltas tracker.
        return $filenameDeltas
    } else {
        # Otherwise, return a null object.
        return @{}
    }
}



# Return any information or alerts about the client's IP address, if it happens to fall within
#  one or more of the "alert" IP subnets defined in the configuration. If any alert subnets are
#  matched from the configuration, they will be included in the returned array.
Function Get-IpAddressAlertSubnets() {
    param([Object]$TargetClient)
    Write-Host "---- Checking the client IP address(es) against alert subnets."
    # Define the alert subnets as any IP addresses matching the given CIDR notation regexes.
    # NOTE: These regexes aren't foolproof, they're only a guide/deterrent.
    $local:alert4Subnets = [System.Collections.ArrayList](
        $global:CliMonConfig.Notifications.IpAddressAlerts.IpRanges -Match `
        '^([0-9]{1,3}\.){3}[0-9]{1,3}\/(3[0-2]|[12]?[0-9])$'
    )
    $local:alert6Subnets = [System.Collections.ArrayList](
        $global:CliMonConfig.Notifications.IpAddressAlerts.IpRanges -Match `
        '^(([0-9a-fA-F]{1,4}:{1,2}){0,7}|::)([0-9a-fA-F]{1,4})\/(1[0-2][0-9]|[0-9]{1,2})$'
    )
    # If the combination of IPv4 and IPv6 addresses doesn't match the total count of the array,
    #  then something is off and the user's attention should be brought to it.
    if(($local:alert4Subnets.Count + $local:alert6Subnets.Count) -ne
      $global:CliMonConfig.Notifications.IpAddressAlerts.IpRanges.Count) {
        Write-Host ("~~~~ The configuration node at 'Config.Notifications." +
            "IpAddressAlerts.IpRanges' contains invalid values!") -ForegroundColor Red
        Write-Host ("~~~~~~ Please ensure the IP subnets configured therein are VALID " +
            "CIDR subnets.") -ForegroundColor Red
    }
    # Running the membership check in two places allows the script to run a detection against
    #  BOTH the IPv4/6 address pools that the client owns, in case they land in an alert subnet
    #  inside of both subnets.
    # NOTE: The "Get-CliMonSubnetMembership" function is defined in the Miscellaneous library file.
    $local:ipv4Memberships = @()
    $local:ipv6Memberships = @()
    if($null -ne $TargetClient.IpAddress) {
        # Check the client against any IPv4 subnets.
        $local:ipv4Memberships =
            Get-CliMonSubnetMembership -HostIps @($TargetClient.IpAddress) -Subnets @($local:alert4Subnets)
    }
    if($null -ne $TargetClient.Ip6Address) {
        # Check the client against any IPv6 subnets.
        $local:ipv6Memberships =
            Get-CliMonSubnetMembership -HostIps @($TargetClient.Ip6Address) -Subnets @($local:alert6Subnets) -IPv6
    }
    # Return a combined array of the two arrays, if anything was captured. Otherwise, keep it $null.
    $local:returnData = $null
    if($local:ipv4Memberships.Count -gt 0) { $local:returnData += $local:ipv4Memberships }
    if($local:ipv6Memberships.Count -gt 0) { $local:returnData += $local:ipv6Memberships }
    return $local:returnData
    #if($local:returnData.Count -gt 0) { return $local:returnData } else { return $null }
}



# Get the most recent report using the "LastWriteTime" filter based on client hostname.
Function Get-ClientReport() {
    param(
        [Object][Parameter(Mandatory=$True)]$TargetClient,
        [Switch]$IsPrior = $False
    )
    if($IsPrior -eq $True) { Write-Host "-- Fetching prior report for client " -NoNewline }
    else { Write-Host "-- Fetching current report for client " -NoNewline }
    Write-Host "$($TargetClient.Hostname)" -ForegroundColor Cyan -NoNewline
    Write-Host "."
    # Attempt to get the TWO most recently-written reports matching the client's hostname.
    $recentReports = @(
        Get-ChildItem -Path "$($global:CliMonConfig.ReportsDirectory)" `
        -Filter "Report-$($TargetClient.Hostname)*" `
        | Sort-Object LastWriteTime -Descending | Select-Object -First 2
    )
    Write-Debug -Message "Two most recent reports:" -Threshold 4 -Prefix '>>>>'
    $recentReports | ForEach-Object { Write-Debug -Message "$_" -Threshold 4 -Prefix '>>>>>>' }
    if(($recentReports.Length -lt 2 -And $IsPrior -eq $True) -Or
      ($recentReports.Length -lt 1)) {
        # If the array only contains only one report (or none), and the script is seeking the "prior"
        #  report, then there was not a prior report in the $ReportsDirectory location.
        # This result also applies if there are NO reports for the client in the reports directory.
        Write-Host "** No prior report found. Setting the comparison object to the default reference."
        return $null
    } else {
        # Otherwise, get the requested report content based on the parameters, using a helper function.
        #  If the switch for "IsPrior" is set, then the second-to-most-recent file is returned.
        $local:whichReport = if($IsPrior -eq $True) { 1 } else { 0 }
        $recentReports = $recentReports[$local:whichReport].Name
        return (Get-ClientReportHelper `
            -TargetClient $TargetClient -TargetFilename $recentReports)
    }
}

# Helper function to get a report from the $ReportsDirectory location, as specified in the config.
#  NOTE: Reviewing the code, it doesn't seem very necessary based on what it's doing, but it's
#  good to have this function to explicitly test the given filename within the ReportsDirectory.
Function Get-ClientReportHelper() {
    param([Object]$TargetClient, [String]$TargetFilename)
    Write-Debug -Message "Called Report Helper for client: $($TargetClient.Hostname)" -Threshold 4 -Prefix '>>>>'
    Write-Debug -Message "Report Filename: $TargetFilename" -Threshold 4 -Prefix '>>>>>>'
    # Use a regex to extract the "date" string from the target filename.
    $local:reportDate = [Regex]::Matches($TargetFilename, '\d{4}-\d{2}-\d{2}-\d{2}_\d{2}')[0].Value
    Write-Debug -Message "Extracted report date: $($local:reportDate)" -Threshold 4 -Prefix '>>>>>>'
    try {
        # Return the content of the filename matching the below pattern, converted from JSON.
        $local:reportContent = (
            Get-Content (
                "{0}\Report-{1}-{2}.txt" -f `
                    $global:CliMonConfig.ReportsDirectory, `
                    $TargetClient.Hostname, `
                    $local:reportDate
            ) | ConvertFrom-Json
        )
        return $local:reportContent
    } catch {
        Write-Host "~~ Could not get the requested client report."
        return $null
    }
}