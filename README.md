# Client-Monitor
A PowerShell script to monitor a client environment for changes (services, startup applications, store apps, scheduled tasks, &amp; installed apps) from a central administrative server, generating reports to view each change per workstation/client.
This script is designed to have monitoring capabilities at the _shortest interval of once per minute_ for reporting changes.


## Monitored Locations & Properties
This script includes monitoring and information-gathering in the following locations.
These variables can change as the script grows and as more locations/fields to track are discovered.
_NOTE: Anything with `(k)` next to it is used as an indexing/unique identifier for the category in the report._

**Store Apps (Name, Architecture, InstallLocation`(k)`, Status, PublisherId, PackageUserInformation)**
- Exclusively uses the `Get-AppxPackage` cmdlet to extract this information, collecting store apps for each user profile on the workstation.

**Installed Applications (PSChildName`(k)`, DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation)**
To check for installed applications, the script monitors three registry locations using the `Get-ItemProperty` cmdlet.
- Local Machine: `HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*`
- Current User: `HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*`
- 64-to-32-bit Applications: `HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*`

**Startup Applications (Name`(k)`, Command, Location, User`(k)`)**
Startup applications can be found in the registry and as an instance of a type _Win32_StartupCommand_.
- `Get-CimInstance Win32_StartupCommand`
- `Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`

**Scheduled Tasks (URI`(k)`, TaskName, Author, SecurityDescriptor, TaskPath)**
- The cmdlet `Get-ScheduledTasks` provides what we need to know here.

**Services (Name`(k)`, DisplayName`(k)`, ServiceName, ServiceType, StartType, Status)**
- Only reliance on the `Get-Service` cmdlet should be needed here, as it provides all contexts for services on the local machine.


## Tweaks
The _"Tweaks_" subsection near the top of the script is used to define static variables that are later expanded in the script, to change its functionality.
Each tweak will include its own descriptive (if it's variable name isn't descriptive enough).

**Current Tweaks Variables**
```
$DomainSuffix
$DomainSuffixRegex

$DomainUserFilter

$ReportsDirectory

$MaxReportRetentionHours

$NotificationsAddress
$NotificationsSource
$NotificationsSubject
$NotificationsServer
$NotificationsServerPort

$NotificationOnNoChange
$NotificationsBodyOnNoChange

$NotificationsAsHTML

$NotificationsHTMLNewValClass
$NotificationsHTMLPriorValClass
$NotificationsHTMLDiffValClass

$NotificationsHTMLWrapper

$NotificationsTriggers = @{
	ReachabilityChange
	InstalledAppsChange
	ServicesChange
	StoreAppsChange
	StartupAppsChange
	ScheduledTasksChange
}
```

## Notifications
Notifications are designed to be generated to a target SMTP relay server (using the Tweaks section), and can have either plaintext or HTML formatting.
Here is a sample notification from a simple _LOCALHOST_ differentiation in a few monitored locations.

A couple things to note with notifications like this:
- The actual values under the changed _Client License Service_ that were changed are highlighted as bold and italic simultaneously.
- Some fields may show up completely empty. This almost always indicates a **null value** was in that field.
- This format can be entirely controlled/restyled within the _Tweaks_ section, as mentioned above.

![Sample Notification from the Monitoring Script](https://raw.githubusercontent.com/NotsoanoNimus/client-monitor/master/docs/Notification_Sample.png)