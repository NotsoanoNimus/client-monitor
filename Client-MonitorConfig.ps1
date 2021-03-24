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



# All variables for Client Monitor configuration will fall under this object, and will
#  be referenced as such. This variable should end up as globally accessible from all modules.
# NOTE: The self-referential variable declarations must come AFTER the definition of the
#        original CliMonConfig variables, otherwise a race condition exists and will cause
#        potentially confusing or destructive results.
$global:CliMonConfig = @{
	# A "safety" variable to ensure the configuration was imported successfully.
	ConfigImported = $True;
	
	# "Dev mode" settings which will override a few of the set config variables, if enabled.
	#  Allows "switching" CliMon profiles easily for testing.
	# Dev mode is enabled via the $global:DevProfileEnabled variable's value, set on script init.
	DevProfile = @{
		# To whom will emails be sent?
		Recipient = [System.Net.Mail.MailAddress]::new('developer@examplesite.co');
		# From who?
		Source = [System.Net.Mail.MailAddress]::new('CliMon Dev <climon-dev@examplesite.co>');
		# What should the email's Subject field be prefixed with to indicate DEV testing?
		SubjectTag = "[DEV] ";
	};

	# When a script-terminating (i.e. Fatal) error is encountered, or if the notification fails
	#  to email properly, the Client Monitor script will forcibly roll back any generated client
	#  reports used for direct comparisons. Setting this to True will tell the script that the
	#  reports added during a failed run of the script (if any) are welcome to stay and not be
	#  deleted. This does NOT affect runs of Ephemeral Mode.
	# NOTE: It is highly recommended to leave this value False, or critical environment updates
	#        could be missed from a botched run or failed notification.
	NoRevert = $False;

	# The prefix or domain name used in the AD environment under which the script will run.
	#  If this is not defined, The $env:COMPUTERNAME variable will be used instead.
	DomainName = "EXAMPLE";
	# The internal domain suffix of the given/extracted hostnames. If this is left blank, then the
	#  self-referential "COMPUTERNAME" environment variable will be populated later. If you are
	#  using Active Directory, PLEASE SET THIS VALUE APPROPRIATELY!
	# Luckily, ping tests and connection tests are done directly by IP address instead of hostname.
	DomainSuffix = '.example.local';
	DomainSuffixRegex = "";   #set in the script initialization.
		
	# MSAD username filter: which clients to collect when running the Get-ADComputer command
	#  (if not supplying a list via the ClientsList parameter).
	# For example:
	#    DomainUserFilter = "(Name -Like 'HOSPITAL-DESKTOP-*') -Or (Name -Like 'FACILITIES-*')"
	# Other examples can include any PowerShell condition/equivalency test, as long as the property
	#  being compared is the "Name" property.
	# Another Example:
	#    DomainUserFilter = "(Name -eq 'DESKTOP-123') -Or
	#                         (Name -Match '\.local$' -And Name -Like 'reception-*')"
	#  This will select all matching hostnames from the directory that are:
	#   A: Equal to DESKTOP-123
	#   B: Ending with '.local' and starting with 'reception-'
	#
	# As a final note, this property can be MANUALLY OVERRIDDEN with a command-line parameter.
	DomainUserFilter = "(Name -Like 'wkstn*')";

	# The folder/location in which to store any generated information for comparison and review.
	ReportsDirectory = "C:\temp\Client-Monitor\Reports";

	# The base directory where all LOCAL user profile folders are stored.
	#   Typically "C:\Users\" in most environments.
	# NOTE: This is a FALLBACK option. The NT registry key for the UserProfile base is actually
	#       checked first before attempting to use the contents of this option.
	UserProfileBase = "C:\Users\";
	# The base folder within a user profile where the NTUSER.DAT file is stored in your environment.
	#  If you're unsure about this, it is best left untouched (as that's most often where it is).
	NTUSERLocation = "\\";
	# A NON-UNC (i.e. CMD-supported) path where NTUSER.DAT files are temporarily duplicated for
	#  mounting to the registry on the end-user's machine. Shadowed files are used instead of
	#  direct access to prevent ruining anything in the user's hive, and to prevent locking.
	# NOTE: This folder is created on the remote machine as an Admin-only folder.
	NTUSERShadowLocation = "C:\temp\Client-Monitor";

	# How many hours to keep reports in the Reports Directory before they're considered expired.
	#  Reports will be deleted from the directory after the script completes a run, if and only if
	#  there were no critical failures during the run of the script.
	# Set this to 0 (or less) to disable the report retention policy.
	MaxReportRetentionHours = 72;

	# How verbose to be with debugging output. The higher, the more descriptive; 0 = no debug, 4 = full verbosity.
	Verbosity = $Debug;  # Currently being set to the passed parameter but can be static as well.

	# Section for realname translation. This allows the script to fetch the "real name" of the target
	#  based on the method used to retrieve it, and will insert that into the notification instead of
	#  the hostname of the target client.
	# NOTE: This section is very configuration-sensitive. If anything is wrong in the configuration,
	#        then the RealnameTranslation will NOT work.
	RealnameTranslation = @{
		# Enables the translation, if True. Note that if a client does not have a real name defined or
		#  the script cannot find the real name based on the options, the value of the IndexedBy field
		#  will be used instead for the client's name in the notification.
		Enabled = $True;
		# The string to attach to the Base URL or the use as the index/key into the DirectObject. This
		#  can be either "IpAddress" or "Hostname", and NOTHING ELSE (or else the translation will fail).
		IndexedBy = "Hostname";
		# The below options set the method for translating hostnames. There are currently two options:
		#  - DirectObject: Use a Hashtable object to translate hostnames directly to real names.
		#  - HTTPRequest: Use an HTTP request to return a real name string for the given hostname or IP.
		Method = "HTTPRequest";
		HTTPRequest = @{
			# The format-ready URL to insert the "index" value into. '{0}' represents a placeholder for
			#  where the IP address or hostname will be entered, based on the IndexedBy value above.
			BaseUrl = ("http://www.fake-url.climon/request.php?keyname={0}");
		}
		DirectObject = @{
			# A one-to-one key/value hashtable that indexes "IndexedBy" value types to their real names.
			#  EXAMPLES:
			#   @{"hostname1"="this name"; "hostname2"="another name"; ...} -- For IndexedBy = "Hostname"
			#   @{"ip1"="this name"; "ip2"="that name"} -- For IndexedBy = "IpAddress"
			Table = @{};
		};
	};

	# These settings are contingent on the DeltasReport parameter being given to the script call.
	DeltasReport = @{
		# If the DeltasReport parameter is included in the call to Client Monitor, and this is set to True,
		#  the report will also attempt to attach the deltas report to the email message. If set to False,
		#  the Deltas Report will only be generated "normally" and will be placed into the Reports
		#  Directory. Off by default.
		AsAttachment = $False;
		# Additionally, set whether or not the Deltas Report should be compressed (i.e. minified).
		Compressed = $False;
	};

	# These settings are contingent on the FlatReportCsv being included with the script call.
	FlatReportCsv = @{
		# Attempt to attach the flat report CSV to the notification email. This would not work without
		#  the notifications being enabled. If set to False, the report will be viewable within the
		#  Reports Directory.
		# NOTE: Even if set to True and notifications are disabled, a written report will still be
		#        output in the Reports Directory location.
		AsAttachment = $False;
		# The delimiter is the character used to separate columns in the CSV file. By default
		#  it is a comma, and it's not recommended to change this value.
		Delimiter = ',';
		# The delimiter replacement will act as a stand-in for the delimiter character if it's found
		#  during the iteration of a Client Profile object. If left blank, the encountered delimiter
		#  character will simply be stripped from the results (so it doesn't ruin the CSV).
		DelimiterReplacement = '';
		# Column Order defines the left-to-right ordering of CSV columns. It is a two-fold variable:
		#  1: Selects only certain properties as desired. Properties that aren't desired in the CSV
		#      can be excluded (like "Architecture", for example) by simply omitting it from the list.
		#  2: As the name implies, this also orders the selected columns left-to-right.
		# PROPERTIES NOT LISTED in TrackedValues that can also be selected (case-sensitive!!!):
		#    "Online", "Invokable", "KeyName", "Hostname", "IpAddress", "Category"
		# IMPORTANT: ALL properties from TrackedValues need to be listed if this value is being defined
		#             manually as a list of columns to order. This is extremely important. A wildcard
		#             operator of '*' can be used as a "catch-all" for the rest of column names.
		# An optional value for this property is simply * -- which will order the columns however the
		#  script sees fit. This is recommended if a certain order isn't desired.
		ColumnOrder = @('Hostname', 'IpAddress', 'Category', 'DisplayName', 'KeyName', '*',
			'Online', 'Invokable');
	}

	# Tracked values across each given category. These values are used in the "Select-Object"
	#  method on the queries for each item in the set returned per category, and also in the
	#  later comparisons.
	# NOTE: Do not include "special" fields used in the script below. Off-limits fields include:
	#  STOREAPPS : PackageUserInformation
	TrackedValues = @{
		InstalledApps = @("DisplayName", "DisplayVersion", "Publisher", "InstallDate", "InstallLocation");
		Services = @("DisplayName", "ServiceName", "StartType");
		StoreApps = @("Name", "Architecture", "InstallLocation", "Status", "PublisherId", "PackageFullName");
		StartupApps = @("Command", "Location", "User");
		ScheduledTasks = @("TaskName", "TaskPath", "Author");
	};
	
	# Settings specific to filename tracking.
	FilenameTracking = @{
		# Enable/Disable filename tracking on the system. This allows for greater control over
		#   environment monitoring by collecting a count of filename patterns on the target.
		Enabled = $True;
		# How many files to show in the "most recent" view in the notification/report.
		ViewLimit = 4;
		# Define which places on the target machine's disk should be checked.
		#  Predefined values should be self-explanatory.
		Locations = @{
			# Uses all directories in the Users folder, typically "C:\Users"; iterates per-user.
			UserProfiles = $True;
			# NOT RECOMMENDED! Uses %SYSTEMROOT%, i.e. "C:\Windows" in most cases.
			SystemFiles = $False;
			# NOT RECOMMENDED! Uses %ProgramData%, i.e. "C:\ProgramData" in most cases.
			ProgramData = $True;
		}
		# Custom directories to check for certain filename patterns. Key/Value pairs are [DIRECTORY]=[RECURSE?] respectively.
		#    So setting "C:\Windows" = $True would order the script to RECURSIVELY check "C:\Windows" for the filename patterns.
		#     ^ that's not a good idea to do, so I've set recursion to $False below.
		CustomLocations = @{
			"C:\Windows\System32" = $False;
			#"C:\otherplace" = $True
		}
		# The filename patterns (regex) to track across all of the above directories. Note that these regexes allow you full control
		#    and are NOT restricted to just filename extension. So take care with this, as entering '.exe' for example will pick up
		#    the filename 'processexecute.txt' because the regex isn't specifying the ^ or $ characters and isn't escaping the .
		# ALSO: The threshold at which the delta will be included in the report. For example, a threshold of 10 means 
		#    that if 10 MORE files than the last check are detected, then it should be rolled into the notification for changes.
		#
		# So the format here is ---> [REGEX] = [THRESHOLD]
		Patterns = @{
			'\.exe$' = 2;
			'\.bat$' = 2;
			'\.enc(rypt(ed)?)?$' = 1;
			'\.te?xt$' = 5;
			'\.html?$' = 1;
		};
	};

	# Notifications-specific settings.
	Notifications = @{
	    # The events or triggers used for notifications to be dispatched to the notifications address.
		#  This section effectively turns them on/off. Names are descriptive enough for the purpose.
		#  These are all enabled by default.
		Triggers = @{
			ReachabilityChange = $True;
			InstalledAppsChange = $True;
			ServicesChange = $True;
			StoreAppsChange = $True;
			StartupAppsChange = $True;
			ScheduledTasksChange = $True;
		};

		# Settings for automatic tracking of InstalledApps version changes.
		InstallationChanges = @{
			# When a notification includes deltas of InstalledApps that have 
			#  "DisplayVersion" and "DisplayName" changes only, append the specific
			#  version to a text file, and automatically add it to the "Changed" section
			#  of the above $Notifications.Filters.InstalledApps.Changed object. For this
			#  to work, $TrackedValues MUST include both "DisplayName" and "DisplayVersion".
			Enabled = $True;
			# If True (and above is enabled), the script will automatically
			#  track/index InstalledApps version changes in the destination file.
			Automatic = $True;
			# The report location is defined in the second half of the configuration.
			# SEE BELOW.
		};

		# Define strings (wildcards supported) which should be white/black-listed for
		#	allowance into notifications. The strings are ARRAYS of patterns. For 
		#	example: @("win*","*micro*") will filter anything starting with "win" and
		#   anything containing the substring "micro".
		# NOTE: These filters apply to ALL data fields in the category and should be used 
		#		with caution. If a service changes from "Group Policy Service" to "Microsoft
		#		GPO Svc" for example, and there's a "micro*" filter, you won't know about 
		#		the change.
		FilterPatterns = @{
			InstalledApps = @{
				New = @();
				Removed = @();
				Changed = @();
			};
			Services = @{
				New = @();
				Removed = @();
				Changed = @();
			};
			StoreApps = @{
				New = @();
				Removed = @();
				Changed = @();
			};
			StartupApps = @{
				New = @();
				Removed = @();
				Changed = @();
			};
			ScheduledTasks = @{
				New = @();
				Removed = @();
				Changed = @();
			};
		};
		FilterOptions = @{
			# Is the filter a blacklist? If so, anything added to the object in the target 
			#  sections is selectively FILTERED OUT. Conversely, if set to False (acting as
			#  a whitelist) then only the given values/patterns will be allowed.
			FiltersBlacklist = $True;
			# Whether or not to show the text of the below tweak in the generated notification,
			#   when an item is filtered out. Default off.
			ShowFilteredItem = $False;
			# Set the mode for filtering to regex. This will cause the strings entered above
			#  to be run against the -Match operator rather than the -Like operator. Do not
			#  change this setting unless you'd like to use regex filtering instead.
			FiltersRegex = $False;
			# A string (HTML formatting optional) to insert when an item is filtered from a
			#  notification, if the above value is $True.
			FilteredIndicator = "<b>Filtered Items</b>";
		};

		# Where to deliver notifications (which email address).
		Recipient = [System.Net.Mail.MailAddress]::new('Notsoano Nimus <postmaster@examplesite.co>');
		# The address used as a 'source' on email notifications.
		Source = [System.Net.Mail.MailAddress]::new('ENV Monitor <desktop-monitor@examplesite.co>');
		# Email notification subject line.
		Subject = 'Summary of User Environment Changes';

		# Alternate body text to use when sending the notification as an attachment instead of inline.
		#  NOTE: This property doesn't reference any other classes or variables by default. If it does,
		#         get changed to do so, the declaration needs to be moved to the bottom of this file.
		AlternateBodyText = "<b>Client Monitor</b> results are attached to this email.<br /><br /><hr />";
		# Is the alternate body text above HTML or plain-text?
		AlternateBodyTextIsHtml = $True;

		# SMTP-related settings.
		Smtp = @{
			# Enable/Disable SSL in the SMTP transaction for dispatching notifications. Turned off by default.
			UseSsl = $False;
			# If the SMTP credential is set to a valid PSCredential object, the script will try to relay using the
			#  given credentials through the target server. Set to $null to use an anonymous relay.
			Credential = $null;
				#(New-Object PSCredential ('monitor@bigcorp.net', `
				#(ConvertTo-SecureString 'SuperSecretPassword' -AsPlainText -Force)))
			# Which mail server to dispatch the notification to/through, and the target relay port.
			Server = 'relay.for.outbound.clientmonitor.mail.net';
			ServerPort = 25;
		}

		# Settings for script crash/failure notification emails.
		#  NOTE: The SMTP-related settings will use the same ones as the above 'Smtp' section.
		OnError = @{
			# Whether or not to even send crash/failure reports.
			Enabled = $True;
			# Destination email address. This will be a plain string.
			Recipient = 'postmaster@examplesite.co';
			# Email subject for the crash notification.
			Subject = '[FATAL] Client Monitor Crash Notification';
			# Body text to include in the message. "[[ERRORTEXT]]" is substituted dynamically for the error text.
			Body = 
				("A fatal error was encountered while running the Client Monitor script. The <strong>top-most</strong>" +
				 " error is the offending line which caused the script to halt, in the event more than one is present." +
				 "<br /><p style='color:red;'>[[ERRORTEXT]]</p>");
		};
		
		# Controls settings that track whether a client's IP address is located within one of the defined
		#  network subnets (IPv4 or IPv6) that are added to the below array. "Alert" simply means that the
		#  header of the client's "changes" section will be modified in the notification to include the
		#  message in a parenthetical manner. These alerts are PERSISTENT and COUNT AS CLIENT "CHANGES", so
		#  if a particular alert continues to be raised, either fix the issue or simply exempt the IP below.
		IpAddressAlerts = @{
			# Whether or not to enable the alert.
			Enabled = $True;
			# Time of day for the window in which IP alerts can be included in notifications.
			DailyTimeStart = "11:56";
			# Allow 100 mins (until approx. 09:36) for a notification in that time to include IP alerts.
			DailyTimeRange = 100;
			# Defined IPv4 and IPv6 subnets that fall within the organization's DHCP ranges. This can also be used to
			#  define subnets that need attention in each notification.
			# ALL subnets must be defined in CIDR notation. See here for help: https://whatismyipaddress.com/cidr
			# This includes SINGLE IP ADDRESSES as well (/32 for IPv4 and /128 for IPv6).
			IpRanges = @(
				"192.168.1.192/26", "172.22.222.0/23"
			);
			# Excluded addresses within the IpRanges above that should NOT raise an alert.
			#  These should NOT be in CIDR notation, as they are single exceptions.
			IpAddressExclusions = @(
				"192.168.1.202", "172.22.223.27"
			);
			# The text to display with the client header. Keep this concise and meaningful.
			#  The "[[IP]]" token is dynamically replaced with the client's IP address and "[[SUBNETS]]" with the matched subnet.
			# NOTE: HTML formatting can also be added to this message as desired.
			Message = ("Client IP <span style='color:steelBlue;font-weight:bold;'>[[IP]]</span> matched subnet(s)" +
				" <span style='color:steelBlue;font-weight:bold;'>[[SUBNETS]]</span>.");
		};
		
		# Variables related to local-admin checks on each workstation.
		LocalAdminTracking = @{
			# Enables local admin tracking, if True.
			Enabled = $True
			# ^REQUIRED: A regular-expression string stating which usernames or username patterns (domain
			#  included) are exempt from being reported as a local administrator on the client machine.
			# NOTE: This string is EXPANDED later in the monitor code, per the ExpandExceptionString option.
			#  If the expansion is breaking this regex, consider changing it or disabling expansion altogether.
			#  One can test this with: $ExecutionContent.InvokeCommand.ExpandString(YOUREXCEPTIONSTRING) at a PSH terminal.
			Exceptions = '^($($env:COMPUTERNAME)\\(corpadmin|Administrator)|EXAMPLE_DOMAIN\\(Administrator|CORPADMIN_[A-Z]+|CoolAdmins))$'
			# See above. Expand variable names in the Exceptions at run-time.
			ExpandExceptionString = $True;
			# The below table is (can be) a mapping of client hostnames -> regexes for exceptions on a per-client basis.
			#  This is useful when, for example, you have a local workstation that requires unusual local admin accounts.
			#  The keys of the table are the hostnames WITH the domain name appended, as applicable (case-insensitive).
			PerClientExceptions = @{
				"WKSTN111.EXAMPLE.LOCAL" = "^EXAMPLE_DOMAIN\\(LOCAL_ADMIN_GUY)"
				"WKSTN222.EXAMPLE.LOCAL" = "^EXAMPLE_DOMAIN\\(TRUSTED_PERSON)"
			};
			# The text to display in the notification about each found account.
			#  The "[[ACCTNAME]]" token is dynamically replaced with the found local admin account name.
			# NOTE: This can also be HTML-formatted.
			Message = ("<em>Discovered local administrator: <span style='font-weight:bold;color:#954ac4;'>[[ACCTNAME]]</span></em>");
		};
		
		# Generate a notification even when there aren't any changes? Disabled by default.
		#  This is more useful for just knowing when the script is running and monitoring if it's actually doing its job.
		NotifyOnNoChange = $False;
		
		# By default, all notifications are sent as a multipart/alternative format, where email clients
		#  can choose to render the email as plaintext or HTML. Setting HTMLEnabled to False indicates
		#  that the user of this script doesn't even want the option available to send as HTML, and
		#  thereby forces the server to send a single Content-Type: text/plain message instead of a
		#  multipart message.
		HTMLEnabled = $True;
		# The two colors to alternate between when switching clients in the HTML notification.
		### The TRUE boolean value is always used first.
		HTMLBackgroundColors = @{
			$True = "FFFFFF"; $False = "EDEDED";
		}
		# Some "advanced" settings for the HTML notifications. These are just class names for certain
		#  classes used within the HTML notifs. The option to change them is present in the event
		#  that the end user has a stylistic reason to do so, or the names are clashing somehow.
		# They're important to define, less important to change.
		HTMLNewValClass = 'NewText';
		HTMLPriorValClass = 'PriorText';
		HTMLDiffValClass = 'DifferentText';
		HTMLChangedValClass = 'ChangedText';
		HTMLSnapshotValClass = 'SnapshotText';
		# Strip out redundant table headers for items that fall under the same client > category.
		HTMLStripTableHeaders = $True;
	};
};


# Dev profile overwrites, if the profile's turned on...
if($global:DevProfileEnabled -eq $True) {
	$global:CliMonConfig.Notifications.Recipient = $global:CliMonConfig.DevProfile.Recipient
	$global:CliMonConfig.Notifications.Source = $global:CliMonConfig.DevProfile.Source
	$global:CliMonConfig.Notifications.Subject =
		$global:CliMonConfig.DevProfile.SubjectTag + $global:CliMonConfig.Notifications.Subject
}


# The second section of the configuration is for self-referential values (variables that need
#  to reference other CliMonConfig variables). These lines must come secondarily due to intermittent
#  race conditions resulting from cross-referencing of a config variable before its definition.


# The full path of the file to read/write for Recent Installations tracking.
#  By default, this is placed in the Reports Directory with a static filename.
$global:CliMonConfig.Notifications.InstallationChanges.ReportLocation =
	"$($global:CliMonConfig.ReportsDirectory)\recentInstallationTracking.log";

# HTML templating for the BODY field of notification emails.
#  [[BODYTEXT]] is replaced dynamically with the generated notification.
# NOTE: Multi-line string definitions require NO WHITESPACE at the start of each new line.
# Something important to note with this is that when defining the notification's HTML style
#  is that if a user's unhappy about the way reports are formatted they are welcome to completely
#  change it around here.
# TIP: To force all tables to keep the same width columns, one could set both MAX-WIDTH and
#       MIN-WIDTH inside the <style> tag to the same value. Keep in mind, however, that although
#       the tables will now come out uniformly, some longer strings may end up getting crushed
#       and word-wrapped in odd places.
$global:CliMonConfig.Notifications.HTMLWrapper = @"
<html>
<head>
<style>
	body { word-wrap: break-word; font-size: 12px; font-family: monospace; }
	table { width: 100%; overflow-x: auto; }
	table, th, td { border: 1px solid black; }
	th, td { text-align: left; padding: 10px; }
	th { background-color: #CCCCCC; }
	td { background-color: #FFFFFF; }
	hr { padding: 0; margin: 10px auto; border: none; }
	p { font-size: 10px; color: black; }
	h1, h2 { padding: 0; margin: 5px 0; }
	h1 { color: #222222; }
	h2 { color: #560D06; }
	.NoChangeHeader { color: #FF2222; padding: 0; margin: 0; }
	.SummaryText { font-size: 14px; color: black; }
	.$($global:CliMonConfig.Notifications.HTMLPriorValClass) { color: #AA2222; font-size: 12px; }
	.$($global:CliMonConfig.Notifications.HTMLNewValClass) { color: #2222AA; font-size: 12px; }
	.$($global:CliMonConfig.Notifications.HTMLSnapshotValClass) { color: #226622; font-size: 12px; }
	.$($global:CliMonConfig.Notifications.HTMLChangedValClass) { color: black; font-size: 12px; }
	.$($global:CliMonConfig.Notifications.HTMLDiffValClass) { font-weight: bold; font-style: italic; }
	.SectionHeader { font-size: 18px; font-weight: bold; text-decoration: underline; }
	div.DiffsSection { margin-left: 18px !important; }
</style>
</head>
<body>
[[BODYTEXT]]
</body>
</html>
"@;

# The header/upper section used in notifications that will have some changes noted for clients.
#  The actual Body text is appended to this value later, forming the [[BODYTEXT]]
#  for the HTML wrapper.
$global:CliMonConfig.Notifications.ChangesBodyHeader = ("<h1>Summary of Environment Changes</h1>`n`n" +
	"<p class='SummaryText'><b><u>QUERY</u></b>: " +
	"$(if($DomainUserFilter -eq ''){$global:CliMonConfig.DomainUserFilter}else{$DomainUserFilter})" +
	"</p>`n<p class='SummaryText'>There were changes detected on the network for the" +
	" following clients. Anything in <span class='" +
	"$($global:CliMonConfig.Notifications.HTMLPriorValClass)'>red</span> is a removed " +
	"property, and anything in <span class='" +
	"$($global:CliMonConfig.Notifications.HTMLNewValClass)'>blue</span> has been added.</p>`n`n");

# A preformatted template for notifications when there is no change to any clients.
$global:CliMonConfig.Notifications.NoChangeBodyText = ("<h1 class='NoChangeHeader'>No Client Changes</h1>`n" +
	"<p class='SummaryText'><b><u>QUERY</u></b>: " +
	"$(if($DomainUserFilter -eq ''){$global:CliMonConfig.DomainUserFilter}else{$DomainUserFilter})" +
	"</p>`n<p class='SummaryText'>There were" +
	" no changes to display for the client machines.<br />`nEither the items that <i>did</i>" +
	" change were filtered, or nothing has changed at all.</p>");