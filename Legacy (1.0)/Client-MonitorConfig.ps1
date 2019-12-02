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



# Flag this file as a valid Client Monitor configuration file.
$CliMonConfig = $True

# The prefix or domain name used in the AD environment under which the script will run.
$DomainName = "TSP"
# The internal domain suffix of the given/extracted hostnames.
$DomainSuffix = '.thestraightpath.local'

# AD username filter; which users to collect when running the Get-ADComputer command (if not supplying a list).
#    Ex: $DomainUserFilter = "(Name -Like 'HOSPITAL-DESKTOP-*') -Or (Name -Like 'FACILITIES-*')"
$DomainUserFilter = "(Name -Like 'wkstn*')"

# The folder in which to store reports for comparison
$ReportsDirectory = "$ENV:WINDIR"

<# How many hours to keep 'reports' in the above directory. After the given hours below,
    reports will be deleted from the directory as the script runs through it.
 #>
$MaxReportRetentionHours = 24

# How verbose to be with debugging output. The higher, the more descriptive; 0 = no debug, 4 = full verbosity.
$DebugVerbosity = $Debug  # Currently being set to the passed parameter but can be static as well.

# The base directory where all LOCAL user profile folders are stored. Typically "C:\Users\" in most environments.
$UserProfileBase = "C:\Users\"
# The base folder WITHIN A USER PROFILE where the NTUSER.DAT file is stored in your environment.
### If you're unsure about this, it is best left untouched.
$NTUSERLocation = "\\"
# A NON-UNC (i.e. CMD-supported) path where NTUSER.DAT files are temporarily duplicated for mounting and analysis.
### NOTE: This folder is created on the remote machine as an Admin-only folder.
$NTUSERShadowLocation = "C:\temp\Client-Monitor"

# Where to deliver notifications (which email address).
$NotificationsAddress = 'postmaster@thestraightpath.email'
# The address used as a 'source' on email notifications.
$NotificationsSource = 'Client Monitor <client-monitor@thestraightpath.email>'
# Email notification subject line.
$NotificationsSubject = "Summary of User Environment Changes"
# Which mail server to dispatch the notification to/through, and the target relay port.
$NotificationsServer = 'relay.internaldomain.withoutauthentication.com'
$NotificationsServerPort = 25

# Enable/Disable SSL in the SMTP transaction for dispatching notifications. Turned off by default.
$NotificationsRelayWithSSL = $False
# If this is set to $True then the script must use the -SmtpCredential parameter with a PowerShell credentials object passed to it.
# See the Examples section of this README document below for more information on how to pass credentials to this script.
$NotificationsRelayWithCredential = $False
 
# Generate a notification even when there aren't any changes? Disabled by default.
#  This is more useful for just knowing when the script is running and monitoring if it's actually doing its job.
$NotificationOnNoChange = $True
# A preformatted template for notifications when there is no change to any clients.
$NotificationsBodyOnNoChange = @"
<h1 class='NoChangeHeader'>No Client Changes</h1>`n
<p class='SummaryText'><b><u>QUERY</u></b>: '$DomainUserFilter'</p>`n
<p class='SummaryText'>There were no changes to display for the client machines.<br />`n
Either the items that <i>did</i> change were filtered, or nothing has changed at all.</p>
"@

# By default, all notifications are sent as HTML.
$NotificationsAsHTML = $True
# The two colors to alternate between when switching clients in the HTML notification.
### The TRUE boolean value is always used first.
$NotificationsHTMLBackgroundColors = @{
	$True = "FFFFFF"; $False = "EDEDED"
}
# "Advanced" settings for the HTML notifications. These are just class names for certain objects used in the HTML notifs.
#    They're important to define, less important to change.
$NotificationsHTMLNewValClass = 'NewText'
$NotificationsHTMLPriorValClass = 'PriorText'
$NotificationsHTMLDiffValClass = 'DifferentText'
# Strip out redundant table headers for items that fall under the same client > category.
$NotificationsHTMLStripTableHeaders = $True
# HTML templating for the BODY field of notification emails.
#  [[BODYTEXT]] is replaced dynamically with the generated notification.
$NotificationsHTMLWrapper = @"
<html>
<head>
<style>
	body { word-wrap: break-word; font-size: 14px; }
	table { width: 100%; overflow-x: auto; }
	table, th, td { border: 1px solid black; }
	th, td { text-align: left; padding: 10px; }
	th { background-color: #CCCCCC; }
	td { background-color: #FFFFFF; }
	tr:hover, td:hover { background-color: #EDEDED; }
	hr { padding: 0; margin: 10px auto; border: none; }
	p { font-size: 12px; color: black; }
	h1, h2 { padding: 0; margin: 5px 0; }
	h1 { color: #222222; }
	h2 { color: #560D06; }
	.NoChangeHeader { color: #FF2222; padding: 0; margin: 0; }
	.SummaryText { font-size: 16px; color: black; }
	.$NotificationsHTMLPriorValClass { color: #AA2222; font-size: 14px; }
	.$NotificationsHTMLNewValClass { color: #2222AA; font-size: 14px; }
	.$NotificationsHTMLDiffValClass { font-weight: bold; font-style: italic; }
	.SectionHeader { font-size: 20px; font-weight: bold; text-decoration: underline; }
	div.DiffsSection { margin-left: 20px !important; }
</style>
</head>
<body>
[[BODYTEXT]]
</body>
</html>
"@

# The header/upper section used in notifications that will have some changes noted for clients.
#    The actual Body text is appended to this value later, forming the [[BODYTEXT]] for the HTML wrapper.
$NotificationsChangesBodyHeader = "<h1>Summary of Environment Changes</h1>`n`n"
$NotificationsChangesBodyHeader += "<p class='SummaryText'><b><u>FILTER QUERY</u></b>: '$DomainUserFilter'</p>`n"
$NotificationsChangesBodyHeader += "<p class='SummaryText'>There were changes detected on the network for the following clients. "
$NotificationsChangesBodyHeader += "Anything in <span class='$NotificationsHTMLPriorValClass'>red</span> is a removed property, "
$NotificationsChangesBodyHeader += "and anything in <span class='$NotificationsHTMLNewValClass'>blue</span> has been added.</p>`n`n"


<# Tracked values across each given category. These values are used in the "Select-Object" method on the queries
    #    for each item in the set returned per category, and also in the later comparisons.
    # NOTE: Do not include "special" fields used in the script below. Off-limits field include:
    #    STOREAPPS : PackageUserInformation
    #>
$TrackedValues = @{
	InstalledApps = @("DisplayName", "DisplayVersion", "Publisher", "InstallDate", "InstallLocation")
	Services = @("DisplayName", "ServiceName", "StartType")
	StoreApps = @("Name", "Architecture", "InstallLocation", "Status", "PublisherId", "PackageFullName")
	StartupApps = @("Command", "Location", "User")
	ScheduledTasks = @("TaskName", "TaskPath", "Author", "SecurityDescriptor")
}


<# The events or triggers used for notifications to be dispatched to the notifications address.
    #    This section effectively turns them on/off. Names are descriptive enough for the purpose.
    #    These are all enabled by default.
    #>
$NotificationsTriggers = @{
	ReachabilityChange = $True
	InstalledAppsChange = $True
	ServicesChange = $True
	StoreAppsChange = $True
	StartupAppsChange = $True
	ScheduledTasksChange = $True
}

# Is the filter a blacklist? If so, anything added to the object in the target sections is selectively FILTERED OUT.
#    Conversely, if set to False (acting as a whitelist) then only the given values/patterns will be allowed.
$NotificationsFiltersBlacklist = $True
# Whether or not to show the text of the below tweak in the generated notification, when an item is filtered out. Default off.
$NotificationsShowFilteredItem = $False
# Set the mode for filtering to regex. This will cause the strings entered below to be run against the -Match operator
#    rather than the -Like operator. Do not change this setting unless you'd like to use regex filtering instead.
$NotificationFiltersRegex = $True
# A string (HTML formatting optional) to insert when an item is filtered from a notification, if the above value is $True.
$NotificationsFilteredIndicator = "<b>Filtered Items</b>"
<# Define strings (wildcards supported) which should be white/black-listed for allowance into notifications.
    #    The strings are ARRAYS of patterns. For example: @("win*","*micro*") will filter anything starting with "win" and
    #    anything containing the substring "micro".
    # NOTE: These filters apply to ALL data fields in the category and should be used with caution.
    #    If a service changes from "Group Policy Service" to "Microsoft GPO Svc" for example, and there's a "micro*" filter,
    #    you won't know about the change.
    #>
$NotificationsFilters = @{
	InstalledApps = @{
		New = @()
		Removed = @()
		Changed = @()
	}
	Services = @{
		New = @()
		Removed = @()
		Changed = @()
	}
	StoreApps = @{
		New = @()
		Removed = @()
		Changed = @()
	}
	StartupApps = @{
		New = @()
		Removed = @()
		Changed = @()
	}
	ScheduledTasks = @{
		New = @()
		Removed = @()
		Changed = @()
	}
}


# When a notification includes deltas of InstalledApps that have "DisplayVersion" and "DisplayName" changes only,
### append the specific version to a text file, and automatically add it to the "Changed" section of the above
### $NotificationsFilters.InstalledApps.Changed object. For this to work, $TrackedValues MUST include both
### "DisplayName" and "DisplayVersion".
$NotificationsRecentInstallationsFiltering = $True
# If True (and above is enabled), the script will automatically track/index InstalledApps version changes in the destination file.
$NotificationsRecentInstallationsAutoTrack = $True
# The full path of the file to read/write for Recent Installations tracking.
### By default, this is placed in the Reports Directory with a static filename.
$NotificationsRecentInstallationsReportLoc = "$ReportsDirectory\recentInstallationTracking.log"


# Enable/Disable filename tracking on the system. This allows for greater control over environment monitoring.
$FilenameTracking = $True
# How many files to show in the "most recent" view in the notification/report.
$TrackedFilenameViewLimit = 4
# Define which places on the target machine's disk should be checked. Predefined values should be self-explanatory.
$TrackedFilenameLocations = @{
	UserProfiles = $True  # Uses all directories in the Users folder, typically "C:\Users", and iterates on a per-uses basis.
	SystemFiles = $False  # NOT RECOMMENDED! Uses %SYSTEMROOT%, i.e. "C:\Windows" in most cases.
	ProgramData = $False  # NOT RECOMMENDED! Uses %ProgramData%, i.e. "C:\ProgramData" in most cases.
}
# Custom directories to check for certain filename patterns. Key/Value pairs are [DIRECTORY]=[RECURSE?] respectively.
#    So setting "C:\Windows" = $True would order the script to RECURSIVELY check "C:\Windows" for the filename patterns.
#     ^ that's not a good idea to do, so I've set recursion to $False below.
$TrackedFilenameLocationsCustom = @{
#	"C:\Windows\System32" = $False
#	"C:\fakeplace" = $True
}
<# The filename patterns (regex) to track across all of the above directories. Note that these regexes allow you full control
    #    and are NOT restricted to just filename extension. So take care with this, as entering '.exe' for example will pick up
    #    the filename 'processexecute.txt' because the regex isn't specifying the ^ or $ characters and isn't escaping the .
    # ALSO: The threshold at which the delta will be included in the report. For example, a threshold of 10 means 
    #    that if 10 MORE files than the last check are detected, then it should be rolled into the notification for changes.
    #
    # So the format here is ---> [REGEX] = [THRESHOLD]
    #>
$TrackedFilenamePatterns = @{
	'\.exe$' = 2
	'\.bat$' = 2
	'\.enc(rypt(ed)?)?$' = 1
	'\.te?xt$' = 5
	'\.html?$' = 1
}