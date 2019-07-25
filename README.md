# Client-Monitor
A PowerShell script to monitor a client environment for changes (services, startup applications, store apps, scheduled tasks, &amp; installed apps) from a central administrative server, generating reports to view each change per workstation/client in one aggregated email notification.
This script is designed to have monitoring capabilities at the _shortest interval of once per minute_ for reporting changes.

When running the script, ensure that the host is an administrator for the target machines across the network, and that the selected hosts have _WinRM_ enabled for execution of remote PowerShell commands.
The security of this (Windows Firewall, SIEM, etc) is completely up to you.


## Monitored Locations & Properties
This script includes monitoring and information-gathering in the following categories/locations.
These variables can change as the script grows. 
Next to each category is the `unique key` format used to keep each tracked item unique.
The format is written as `$(PropertyName)` for each field, where `PropertyName` is a field that can be _selected_ from the cmdlet used to get the information from the category.

If this still doesn't make sense, take a look at the generated reports.
You'll notice that each `Index` section is identifying a list of the keynames used in the actual corresponding category.
These keynames are created from the properties/fields of each category as shown below.

Of course, the only issue with this is that when one of these variables inevitably changes, it will be considered a new key.
This means that the script will recognize the new index/keyname in the **New** classification rather than **Changed**.
The fields chosen may be the most "unique" amongst their class but they also might be vulnerable to constantly rotating their values used to build the keyname.
Such is inevitable, and it's generally easy to pick up on this change in the notification/digest.

**Store Apps `$(InstallLocation)_$(PackageFullName)`**
- Exclusively uses the `Get-AppxPackage` cmdlet to extract this information, collecting store apps for each user profile on the workstation.

**Installed Applications `$(PSChildName)_{HKLM | HKCU | 6432Node}`**
To check for installed applications, the script monitors three registry locations using the `Get-ItemProperty` cmdlet.
- Local Machine: `HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*`
- Current User: `HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*`
- 64-to-32-bit Applications: `HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*`

**Startup Applications `$(Name)_$(User)`**
Startup applications can be found in the registry and as an instance of a type _Win32_StartupCommand_.
- `Get-CimInstance Win32_StartupCommand`
- `Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`

**Scheduled Tasks `$(URI)`**
- The cmdlet `Get-ScheduledTasks` provides what we need to know here.

**Services `$(DisplayName)_$(Name)`**
- Only reliance on the `Get-Service` cmdlet should be needed here, as it provides all contexts for services on the local machine.

---

## Parameters

#### ClientsList {"list.txt"}
**Optional**. A list of line-separated client IP addresses/hostnames to monitor. This can include invalid items or typos and the script will filter it out.
For example, the following list _"clients.txt"_ will cause the script to monitor `192.168.123.12`, `WKSTN39`, and `WKSTN107` but the invalid IP in the list will be silently dropped/skipped.
```
192.168.123.12
\\WKSTN39
1926.168.123.13
WKSTN107
```

#### DeltasReport
**Optional**. If included as a switch to the script, a _DELTAS_ text file with the primary deltas/changes object will be generated in the reports directory.
The report should only be generated if any changes were detected. This is useful for debugging notification truthfulness, for example.

#### NoNotifications
**Optional**. Exactly as it says: a switch to the script that forces the script to skip sending an email notification.

#### BCC {"target@target.net, Notsoano Nimus \<test@testing.com\>"}
**Optional**. If included, the script will BCC the target address(es) in the generated notifications.
Take care and precaution that the _relay server_ used in the Tweaks section below will accept relay mail to all target destinations.

---

## Tweaks
The _"Tweaks_" subsection near the top of the script is used to define static variables that are later expanded in the script, to change its functionality.
Each tweak will include its own description (if its variable name isn't descriptive enough).

#### Current Tweaks Variables
+ **$DomainSuffix** -- The internal domain suffix of the given hostnames.
+ **$DomainSuffixRegex** -- DO NOT MODIFY, unless the above domain suffix includes special regex characters beyond a period.
+ **$DomainUserFilter** -- AD username filter; which users to collect when running the `Get-ADComputer` command (if _not_ supplying a list).
  + _Example_: `$DomainUserFilter = "(Name -Like 'HOSPITAL-DESKTOP-*') -Or (Name -Like 'FACILITIES-*')"`
+ **$ReportsDirectory** -- The folder in which to store reports generated by the script (and also where to look for prior reports).
+ **$MaxReportRetentionHours** -- The maximum amount of hours to keep a report in the `$ReportsDirectory` location.
  + If the most recent report in the directory is **older** than the `$MaxReportRetentionHours` time, it will actually be _used for comparison before it is deleted_.
+ **$TrackedValues** -- Tracked values across each given category. These values are used in the `Select-Object` method on the queries for each item in the set returned per category, and also in the later **comparisons**. Below are the defaults for each category:
  + _InstalledApps_ : `@("DisplayName", "DisplayVersion", "Publisher", "InstallDate", "InstallLocation")`
  + _Services_ : `@("DisplayName", "ServiceName", "ServiceType", "StartType", "Status")`
  + _StoreApps_ : `@("Name", "Architecture", "InstallLocation", "Status", "PublisherId")`
  + _StartupApps_ : `@("Command", "Location", "User")`
  + _ScheduledTasks_ : `@("TaskName", "TaskPath", "Author", "SecurityDescriptor")`
  + **IMPORTANT**: There are certain fields that are _off limits_ to add to these string arrays. **DO NOT USE THESE IN THE ABOVE TWEAK!** If present, they are listed below for each category:
    + _StoreApps_ : `PackageUserInformation`
+ **$NotificationsAddress** -- The target email address for notifications.
+ **$NotificationsSource** -- The "From" address of emails sent from the script.
+ **$NotificationsSubject** -- The subject line used in email notifications.
+ **$NotificationsServer** -- A target server used to relay emails to their destination. This is _required_ to send notifications.
+ **$NotificationsServerPort** -- The relay server's target port.
+ **$NotificationOnNoChange** -- If set, will generate a notification even if there wasn't a change detected across the clients.
  + **$NotificationsBodyOnNoChange** -- Body template for notifications informing of no changes.
+ **$NotificationsAsHTML** -- Whether or not to send emails with HTML formatting. If set to `$False` email notifications will be sent in plaintext.
  + The "class" tweaks in this section are really not important unless the name is clashing with another CSS class you write.
+ **$NotificationsHTMLWrapper** -- The HTML notification wrapper format, including all content between the `<HTML>` tags. The `[[BODYTEXT]]` item here is later replaced with the generated body of the notification.
+ **$NotificationsChangesBodyHeader** -- The header/upper section used in notifications that _will_ have some changes noted for clients.
  + The actual Body text is appended to this value _later_, forming the `[[BODYTEXT]]` piece to fit inside the **HTML wrapper tweak**.
+ **$NotificationsTriggers** -- Turn on/off delta detections for the listed sections or items. If set to `$False`, the notification will not include change information about the given section.
  + _ReachabilityChange_ : Notify when the reachability of the target host changed (both a ping test and `Invoke-Command` test for WinRM).
  + _InstalledAppsChange_ : Notify when installed applications change.
  + _ServicesChange_ : Notify when services change.
  + _StoreAppsChange_ : Notify when store applications change.
  + _StartupAppsChange_ : Notify when applications run at system startup change.
  + _ScheduledTasksChange_ : Notify when the scheduled tasks of a system are modified.
+ **$NotificationsFiltersBlacklist** -- Is the filter a blacklist (default is yes)? If so, anything added to the below object in the target sections is selectively *FILTERED OUT*. Conversely, if set to `$False` (acting as a whitelist) then only the given values/patterns will be allowed.
+ **$NotificationsShowFilteredItem** -- _**Off** by default_. Whether or not to show the text of the below tweak in the generated notification, when an item is filtered out.
+ **$NotificationsFilteredIndicator** -- A string (HTML formatting optional) to insert when an item is filtered from a notification, if the above value is `$True`.
+ **$NotificationsFilters** -- Define strings (_wildcards supported_) which should be white/black-listed for allowance into notifications. The strings are **arrays** of patterns. For example: `@("win*","*micro*")` will filter anything starting with `"win"` and anything containing the substring `"micro"`. Sub-field names are pretty self-explanatory.
  + These filters apply to **ALL data fields** in the category and should be used with caution. If a service changes from "Group Policy Service" to "Microsoft GPO Svc" for example, and there's a `"micro*"` filter, you won't know about the change.
  + Despite having a notification filter in place, if using the `DeltasReport` parameter, deltas that were filtered out _can_ still be viewed within the generated Deltas Report.

---

## Notifications
Notifications are designed to be generated to a target SMTP relay server (using the Tweaks section), and can have either plaintext or HTML formatting.
Here is a sample notification from a simple _LOCALHOST_ differentiation in a few monitored locations.

A couple things to note with notifications like this:
- The actual values under the changed _Client License Service_ that were changed are highlighted as bold and italic simultaneously.
- Some fields may show up completely empty. This almost always indicates a **null value** was in that field.
- This format can be entirely controlled/restyled within the _Tweaks_ section, as mentioned above.

![Sample Notification from the Monitoring Script](https://raw.githubusercontent.com/NotsoanoNimus/client-monitor/master/docs/Notification_Sample.png)

---

## TODOs
- ~~If filters are engaged and _NOTHING_ is in the report except a few blank sections (because things were filtered out), appropriately send the "No Changes" email to indicate that no **tracked changes** were discovered.~~
- ~~Make compared & selected fields from each category (StoreApps, Services, etc) dynamic using a single tweak. Basically allow a single tweak to define which fields are discovered and compared among the categories.~~