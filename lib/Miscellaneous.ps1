<#
 # Miscellaneous.ps1
 #
 # This is a simple library which provides functions that don't quite fit into
 #  the other areas and "zones" of the Client Monitor script.
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



# Called by the main method. Display the environment and expected running usage of the
#  script based on the initially-supplied parameters to the Client-Monitor call.
Function Show-ClientMonitorRuntimeEnvironment() {
    Write-Host "Client Monitor runtime configuration:" -ForegroundColor Green
    # DEBUG SECTION. DISPLAYS ALL COMMAND-LINE PARAMETER VARIABLES IF DEBUGGING IS ENABLED.
    if($global:CliMonConfig.Verbosity -gt 0) {
        Write-Host "Debug: Debugging is enabled. Verbosity set to $($global:CliMonConfig.Verbosity)."
        Write-Host "-- Client Monitor Parameters:"
        Write-Host "---- [int]`$Debug = $Debug"
        Write-Host "---- [String]`$ClientsList = $ClientsList"
        Write-Host "---- [Switch]`$DeltasReport = $DeltasReport"
        Write-Host "---- [Switch]`$NoNotifications = $NoNotifications"
        Write-Host "---- [String]`$BCC = $BCC"
        Write-Host "---- [Switch]`$NoMini = $NoMini"
        Write-Host "---- [String]`$DomainUserFilter = $DomainUserFilter"
        Write-Host "---- [Switch]`$SnapshotMode = $SnapshotMode"
        Write-Host "---- [Switch]`$NoFilters = $NoFilters"
        Write-Host "---- [Switch]`$AsAttachment = $AsAttachment"
        Write-Host "---- [Switch]`$FlatReportCsv = $FlatReportCsv"
        Write-Host "---- [Switch]`$Ephemeral = $Ephemeral"
        Write-Host "---- [String]`$ConfigFile = $ConfigFile"
        Write-Host "---- [PSCredential]`$SmtpCredential = $SmtpCredential"
    }
    if($Ephemeral -eq $True) {
        Write-Host "EPHEMERAL: The script is running in Ephemeral mode."
        Write-Host ("-- No tracked changes across clients will be saved, only captured and displayed" +
            " during the current run.")
    }
    if($ClientsList -eq 'use-AD-list') {
        Write-Host ("ClientsList: No parameter supplied. The script is assuming the" +
            " Get-ADComputer cmdlet will suffice for retrieveing target clients.")
        if($DomainUserFilter -ne "" -And $null -ne $DomainUserFilter) {
            $global:CliMonConfig.DomainUserFilter = $DomainUserFilter
        }
        if($global:CliMonConfig.DomainUserFilter -ne "") {
            Write-Host ("-- DomainUserFilter: Hosts retrieve from the AD server will be filtered" +
                " with: $($global:CliMonConfig.DomainUserFilter)")
        }
    } else {
        Write-Host ("ClientsList: Using list at '{0}'" -f $ClientsList)
    }
    if($NoFilters -eq $False) {
        Write-Host "NoFilters: Content filters are ACTIVE and READY."
    } else {
        Write-Host "NoFilters: Content filters are DISABLED and WAITING."
    }
    if($DeltasReport -eq $True) {
        Write-Host "DeltasReport: A deltas report will be generated."
        if($global:CliMonConfig.DeltasReport.AsAttachment -eq $True -And $NoNotifications -eq $False) {
            Write-Host "-- The Deltas Report will be included as an attachment to the email."
        }
        if($global:CliMonConfig.DeltasReport.Compressed -eq $True) {
            Write-Host "-- The Deltas Report will be compressed."
        }
    }
    if($FlatReportCsv -eq $True) {
        Write-Host "FlatReportCsv: A CSV report of all user items will be generated."
        if($global:CliMonConfig.FlatReportCsv.AsAttachment -And $NoNotifications -eq $False) {
            Write-Host "-- The Flat Report will be included as an attachment to the email."
        }
    }
    if($NoNotifications -eq $True) {
        Write-Host "NoNotifications: The script will not issue any notification emails."
    } else {
        if($global:CliMonConfig.Notifications.NotifyOnNoChange -eq $True) {
            Write-Host "A notification will be included even if there are no changes."
        } else {
            Write-Host "A notification will be generated, unless there are no changes to output."
        }
        if($AsAttachment -eq $True) {
            Write-Host "-- AsAttachment: The notification will be sent as an attachment rather than inline."
        }
        $local:notifType =
            if($global:CliMonConfig.Notifications.HTMLEnabled -eq $True) {"HTML"} else {"Plain-Text"}
        Write-Host "-- HTMLEnabled: Notifications will be sent as: $($local:notifType)"
    }
    if($BCC -ne "") {
        Write-Host ("BCC: The following additional recipients will silently receive" +
            " a copy of the notification:")
        Write-Host "-- $BCC"
    }
    if($NoMini -eq $True) {
        Write-Host "NoMini: Reports generated by the script will NOT be compressed."
        Write-Host "-- This can take up more than 3x more space than using JSON compression."
    }
    if($global:CliMonConfig.MaxReportRetentionHours -gt 0) {
        Write-Host ("Report Retention: Reports aged beyond " +
            "$($global:CliMonConfig.MaxReportRetentionHours) hours will be deleted.")
    } else {
        Write-Host "Report Retention: The retention policy for aged reports is disabled."
    }
    if($SnapshotMode -eq $True) {
        Write-Host ("SnapshotMode: The script will run in an ephemeral 'snapshot' mode to capture" +
            " all information across the target hosts.")
        if($NoFilters -eq $True) {
            Write-Host "-- NoFilters: The resulting snapshot will NOT have any filters applied."
        } else {
            Write-Host "-- The resulting snapshot will be filtered. Use -NoFilters to avoid this."
        }
    } elseif($SnapshotMode -eq $False -And $NoFilters -eq $True) {
        Write-Host "NoFilters: Notifications will not have any of the deltas filtered."
    }
    if($null -ne $SmtpCredential) {
        Write-Host "SmtpCredential: There were credentials for SMTP supplied to the script."
    }
}



# Update and verify all configuration references.
#  This is the second task of the main method.
Function Update-ScriptConfiguration() {
    Write-Debug -Message "Updating the script configuration post-sourcing." -Threshold 1 -Prefix '>>'
    # If the DomainName isn't defined, use the ComputerName variable instead.
    #  This helps with SID processing.
    if($global:CliMonConfig.DomainName -eq "" -Or $null -eq $global:CliMonConfig.DomainName) {
        Write-Debug -Message ("The `"DomainName`" variable is blank. Using %ComputerName% instead: " +
            "$env:COMPUTERNAME") -Threshold 2 -Prefix '>>>>'
        $global:CliMonConfig.DomainName = $env:COMPUTERNAME
    }
    # Test the InstallationChanges ReportLocation variable, and create a file if it doesn't exist.
    if($global:CliMonConfig.Notifications.InstallationChanges.Enabled -eq $True) {
        if(-Not(Test-Path $global:CliMonConfig.Notifications.InstallationChanges.ReportLocation)) {
            Write-Debug -Message "The installation tracking report wasn't found. Creating an empty one." -Threshold 2 -Prefix '>>>>'
            (@{} | ConvertTo-Json) | Out-File -Force `
                -FilePath "$($global:CliMonConfig.Notifications.InstallationChanges.ReportLocation)"
        }
    }
    # Check for an empty DomainSuffix. If it's empty, use the COMPUTERNAME environment variable instead.
    if($global:CliMonConfig.DomainSuffix -eq "" -Or $null -eq $global:CliMonConfig.DomainSuffix) {
        $global:CliMonConfig.DomainSuffix = ".$($env:COMPUTERNAME)"
        Write-Debug -Message "The DomainSuffix configuration is blank; using '.$env:COMPUTERNAME'" -Threshold 2 -Prefix '>>>>'
    }
    # Populate the DomainSuffix regex field.
    $global:CliMonConfig.DomainSuffixRegex =
        if($global:CliMonConfig.DomainSuffix -Is [String]) {
            [Regex]::Escape($global:CliMonConfig.DomainSuffix)
        } else { "" }
    Write-Debug -Message "Populated the DomainSuffixRegex field: $($global:CliMonConfig.DomainSuffixRegex)" -Threshold 2 -Prefix '>>>>'
    # If the DomainUserFilter parameter is defined, override the configuration variable here.
    if($DomainUserFilter -ne "" -And $null -ne $DomainUserFilter) {
        Write-Debug -Message "Overriding configuration for DomainUserFilter: `"$DomainUserFilter`"" -Threshold 2 -Prefix '>>>>'
        # If the DomainUserFilter is present under the notifications variables, replace it.
        @("ChangesBodyHeader", "NoChangeBodyText", "HTMLWrapper") | ForEach-Object {
            $global:CliMonConfig.Notifications.$_ =
                ($global:CliMonConfig.Notifications.$_ -Replace `
                [Regex]::Escape($global:CliMonConfig.DomainUserFilter), `
                "$DomainUserFilter")
        }
        # Finally, set the user filter override.
        $global:CliMonConfig.DomainUserFilter = $DomainUserFilter
    }
    # Check to ensure that "PackageUserInformation" is NOT included in the TrackedValues.StoreApps
    #  object. I know, I know, I'm supposed to "trust the user" on this one. :)
    if($global:CliMonConfig.TrackedValues.StoreApps -IContains "PackageUserInformation") {
        Write-Debug -Message "Removing 'PackageUserInformation' from the StoreApps tracking." -Threshold 2 -Prefix '>>>>'
        $global:CliMonConfig.TrackedValues.StoreApps = 
            $global:CliMonConfig.TrackedValues.StoreApps | ForEach-Object {
                if($_ -ne "PackageUserInformation") { $_ }
            }
    }
}



# Called by the main function as the last method call. Cleans up the environment and "stale" reports.
#  If the "TrappedError" switch is set, DO NOT remove old reports, and roll back any reports made by
#  this run of the script. This does NOT include delta reports and such. TrappedError should only ever
#  be triggered by a fatal script failure or a general failure to dispatch the notification email.
Function Invoke-CliMonCleanup() {
    param([Switch]$TrappedError = $False)
    Write-Debug -Message "Running Client Monitor cleanup tasks." -Threshold 1 -Prefix '>>'
    if(($TrappedError -eq $True -And $global:CliMonConfig.NoRevert -eq $False) -Or
      $Ephemeral -eq $True) {
        if($Ephemeral -eq $False) {
            Write-Host ("~~ A critical error was encountered." +
                " Reverting all client reports and trackers for this session.")
        } elseif($Ephemeral -eq $True) {
            Write-Host ("-- The script was running in Ephemeral Mode. Reverting all client reports" +
                " and trackers for this session.")
        }
        Write-Debug -Message "The script appears to have exited in error or in a temporary state." -Threshold 2 -Prefix '>>>>'
        if($global:CliMonEmailFailure -eq $True) {
            Write-Host "~~~~ The email notification failed to dispatch. Please check your settings."
            Write-Host "~~~~ SMTP Error Description: $($global:CliMonEmailErrorText)"
        }
        # If ephemeral is NOT engaged, and NoRevert is True, do NOT remove the reports.
        if($Ephemeral -eq $False -And $global:CliMonConfig.NoRevert -eq $True) { return }
        # An error was trapped in some way. Remove any reports generated in this session.
        Write-Debug -Message "Removing reports generated in this session." -Threshold 2 -Prefix '>>>>'
        $global:CliMonGeneratedReports | ForEach-Object {
            Write-Debug -Message "Report: $_" -Threshold 3 -Prefix '>>>>>>'
        }
        foreach($report in $global:CliMonGeneratedReports) {
            # Check for the file's existence, then try to delete it.
            if(Test-Path $report) {
                try {
                    Remove-Item -Path $report -Force
                    Write-Debug -Message "Report '$report' removed." -Threshold 3 -Prefix '>>>>>>'
                } catch { }
            }
        }
    } else {
        Write-Debug -Message "The script appears to have exited normally." -Threshold 2 -Prefix '>>>>'
        # If the MaxReportRetentionHours setting is set to zero (or less), reports don't get cleaned.
        if($global:CliMonConfig.MaxReportRetentionHours -gt 0) {
            # Delete reports in the ReportsDirectory that exceed the age threshold.
            Write-Host "-- Removing reports that have aged beyond $($global:CliMonConfig.MaxReportRetentionHours) hours."
            # Get the current time that matches the filename format for reports.
            $local:todaysDate = ((Get-Date -UFormat %Y-%m-%d-%H_%M).ToString())
            # Get the list of Report-*.txt files in the Reports Directory
            $local:reportFiles = (Get-ChildItem -Path `
                "$($global:CliMonConfig.ReportsDirectory)").Name -ILike 'Report-*.txt'
            # Go through each report file, extract the date from the name, and test it for expiration.
            foreach($report in $local:reportFiles) {
                Write-Debug -Message "Examining report: $report" -Threshold 3 -Prefix '>>>>'
                $report -Match '-(\d{4}-\d{2}-\d{2}-\d{2}_\d{2}).txt$' | Out-Null
                # If the extracted match's date is beyond the expiration timer, delete the file.
                if((Get-DateDeltaHours -moreRecentDate $local:todaysDate `
                  -lessRecentDate "$($matches[1])") -ge $global:CliMonConfig.MaxReportRetentionHours) {
                    Remove-Item -Confirm:$False -Force -Path `
                        "$($global:CliMonConfig.ReportsDirectory)\$report"
                    Write-Host "---- Removed aged report: $report"
                }
            }
        }
        # If application auto-tracking is enabled, set the content of the report to the newly-tracked
        #  InstalledApps that had a version change.
        if($global:CliMonConfig.Notifications.InstallationChanges.Enabled -eq $True) {
            # If there were changes to the automatic tracking file, record them.
            if($global:CliMonAutoTrackingIndexChanged -eq $True) {
                Write-Host "-- Saving updated installed application trackers."
                ($global:CliMonUpdatedApplicationTrackingFilters | ConvertTo-Json) `
                    | Set-Content -Force -Path `
                    $global:CliMonConfig.Notifications.InstallationChanges.ReportLocation
            }
        }
    }
    # Regardless of either outcome, clean up ANY custom variables as needed.
    Remove-Variable * -ErrorAction SilentlyContinue
    $error.Clear()
    # Regardless of the exit type, if the global timer is running, stop it.
    if($global:CliMonGenTimer.IsRunning -eq $True) { $global:CliMonGenTimer.Stop() }
}

# Helper function for report cleanup. Compare two dates and return the difference in hours
#  between the two times. Since the dates are coming from filenames (which can't have a ':'
#  character in their names), any underscores extracted from the name are replaced with ':'.
Function Get-DateDeltaHours() {
    param([String]$moreRecentDate, [String]$lessRecentDate)
    $moreRecentDate = $moreRecentDate -Replace '_', ':'
    $lessRecentDate = $lessRecentDate -Replace '_', ':'
    return ((Get-Date "$moreRecentDate") - (Get-Date "$lessRecentDate")).TotalHours
}



# Define the Write-Debug function on the target client. The given threshold value is the script
#  'verbosity' level (defined in either the 'Debug' parameter or the Client Monitor configuration
#  manually) that must be set in order to see the message.
# For example: Write-Debug -Message 'Test' -Prefix '>>' -Threshold 3
#  This means that in order to display the '>> Test' message to STDOUT, the configuration must have
#  a "Verbosity" of 3 or more (if configured staticly) or a -Debug parameter of 3 or more.
Function Write-Debug() {
    param([int]$Threshold = 10000, [String]$Message, [String]$Prefix = "")
    # If the threshold parameter is LESS THAN OR EQUAL TO the configured/passed Debug level...
    if($Threshold -le $global:CliMonConfig.Verbosity) {
        # Get the time/date.
        & Write-Host "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss') " `
            -ForegroundColor DarkCyan -BackgroundColor Black -NoNewline
        # Write out the threshold level that was crossed (Debug Verbosity).
        & Write-Host "[$Threshold] " -ForegroundColor Yellow -BackgroundColor Black -NoNewline
        # Write out the given prefix; usually a series of angle brackets works well: '>>'
        & Write-Host "$($Prefix) " -ForegroundColor Cyan -BackgroundColor Black -NoNewline
        # Finally, write the message.
        & Write-Host "$Message" -ForegroundColor Magenta -BackgroundColor Black
    }
}