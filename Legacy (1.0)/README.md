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

**Store Apps `$(PackageFullName)`**
- Exclusively uses the `Get-AppxPackage` cmdlet to extract this information, collecting store apps for each user profile on the workstation.

**Installed Applications `$(PSChildName)_{HKLM | HKCU | 6432Node}`**
- To check for installed applications, the script monitors three registry locations using the `Get-ItemProperty` cmdlet.
- Local Machine: `HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*`
- Current User: `HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*`
- 64-to-32-bit Applications: `HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*`

**Startup Applications `$(Name)_$(User)`**
- Startup applications can be found in the registry and as an instance of a type _Win32_StartupCommand_.
- `Get-CimInstance Win32_StartupCommand`
- `Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`

**Scheduled Tasks `$(URI)`**
- The cmdlet `Get-ScheduledTasks` provides what we need to know here.

**Services `$(DisplayName)_$(Name)`**
- Only reliance on the `Get-Service` cmdlet should be needed here, as it provides all contexts for services on the local machine.


### Filename Monitoring
As discussed in the below _Configuration File_ section, the script comes with the additional option to define regular expressions to match against filenames in certain predefined (as well as custom) directories.
This is helpful for **tracking** a list of suspicious extensions (e.g. _enc_, _777_, _enigma_, etc), as well as well-known ones (like _exe_, _bat_, etc).

Also, extensions don't have to be targeted, if for example it was desired to just monitor filenames containing timestamps (e.g. "filename-2017-07-11-read.txt" with the regex `\d{4}-\d{2}-\d{2}`).
Again, see the below section for some examples.

---

## Parameters

### ClientsList {"list.txt"}
**Optional**. A list of line-separated client IP addresses/hostnames to monitor. This can include invalid items or typos and the script will filter it out.
For example, the following list _"clients.txt"_ will cause the script to monitor `192.168.123.12`, `WKSTN39`, and `WKSTN107` but the invalid IP in the list will be silently dropped/skipped.
```
192.168.123.12
\\WKSTN39
1926.168.123.13
WKSTN107
```
If a ClientsList parameter is _NOT_ passed to the script, the script will attempt to use the cmdlet `Get-ADComputer` to find client machines, using the `$DomainUserFilter` configuration as discussed in the below section.

### DeltasReport
**Optional**. If included as a switch to the script, a _DELTAS_ text file with the primary deltas/changes object will be generated in the reports directory.
The report should only be generated if any changes were detected. This is useful for debugging notification truthfulness, for example.

### NoNotifications
**Optional**. Exactly as it says: a switch to the script that skips sending any kind of email notification.

### BCC {"email-address(es)"}
**Optional**. If included, the script will BCC the target address(es) in the generated notifications.
Take care and precaution that the _relay server_ used in the Configuration File section below will accept relay mail to all target destinations.

### NoMini
**Optional** switch. If set, do _not_ minify or compress the JSON reports generated by the script in the `Write-Report` function.
This is useful for getting a full view of each clients report, but _beware_, the whitespace added to the file almost **quadruples** the file size!

### Debug {Verbosity Level}
**Optional** integer. If set to _1_ or greater, then script will output debugging information. Useful for administrators that may wonder why information is missing from some reports.
  + _1_ : Lowest verbosity.
  + _4_ : Highest verbosity.

### ConfigFile {full-path}
**Optional**. Defaults to _".\Client-MonitorConfig.ps1"_, but can be the full path of a Client Monitor configuration file.

### SmtpCredential {Powershell-Credential-Object}
**Optional** PowerShell Credentials object. If provided to the script, use the credentials to relay the notifications through the target server/port.
In order to make use of this, the _config_ for `$NotificationsRelayWithCredential` **must** be set to `$True`!

---

## Configuration File
The configuration file (_Client-MonitorConfig.ps1_) is used to define static variables that are expanded in the script, to tailor its functionality. Each config variable will include its own description (if its variable name isn't descriptive enough).

#### Current Config Variables
+ **$CliMonConfig** -- Should always return _$True_. This is a sanity-check to ensure that the given configuration file is a valid Client Monitor configuration.
+ **$DomainName** -- The prefix or domain name used in the AD environment under which the script will run.
+ **$DomainSuffix** -- The internal domain suffix of the given hostnames.
+ **$DomainSuffixRegex** -- DO NOT MODIFY, unless the above domain suffix includes special regex characters beyond a period.
+ **$DomainUserFilter** -- AD username filter; which users to collect when running the `Get-ADComputer` command (if _not_ supplying a list).
  + _Example_: `$DomainUserFilter = "(Name -Like 'HOSPITAL-DESKTOP-*') -Or (Name -Like 'FACILITIES-*')"`
+ **$ReportsDirectory** -- The folder in which to store reports generated by the script (and also where to look for prior reports).
+ **$MaxReportRetentionHours** -- The maximum amount of hours to keep a report in the `$ReportsDirectory` location.
  + If the most recent report in the directory is **older** than the `$MaxReportRetentionHours` time, it will actually be _used for comparison before it is deleted_.
+ **$DebugVerbosity** -- How verbose to be with debugging output.
  + By default, this is set to the passed paramter, but can be manually overridden with an integer value.
  + The _higher_, the _more_ descriptive; **0** = no debug, **4** = full verbosity.
+ **$UserProfileBase** -- The base directory where all _local_ user profile folders are stored. Typically **C:\Users\\** in most environments.
+ **$NTUSERLocation** -- The base folder _within a user profile_ where the _NTUSER.DAT_ file is stored in your environment.
  + If you're unsure about this, it is best left untouched.
+ **$NTUSERShadowLocation** -- A **NON-UNC** (i.e. _CMD-supported_) path where _NTUSER.DAT_ files are temporarily duplicated for mounting and analysis.
  + ~~_NOTE_: This folder is created on the remote machine as an Admin-only folder.~~ **TODO:** FIX THIS.
+ **$TrackedValues** -- Tracked values across each given category. These values are used in the `Select-Object` method on the queries for each item in the set returned per category, and also in the later **comparisons**. Below are the defaults for each category:
  + _InstalledApps_ : `@("DisplayName", "DisplayVersion", "Publisher", "InstallDate", "InstallLocation")`
  + _Services_ : `@("DisplayName", "ServiceName", "StartType")`
  + _StoreApps_ : `@("Name", "Architecture", "InstallLocation", "Status", "PublisherId", "PackageFullName")`
  + _StartupApps_ : `@("Command", "Location", "User")`
  + _ScheduledTasks_ : `@("TaskName", "TaskPath", "Author", "SecurityDescriptor")`
  + **IMPORTANT**: There are certain fields that are _off limits_ to add to these string arrays. **DO NOT USE THESE IN THE ABOVE VARIABLE!** If present, they are listed below for each category:
    + _StoreApps_ : `PackageUserInformation`
+ **$NotificationsAddress** -- The target email address to which notifications are sent.
+ **$NotificationsSource** -- The "From" address of emails sent from the script.
+ **$NotificationsSubject** -- The subject line used in email notifications.
+ **$NotificationsRelayWithSSL** -- Enable/Disable SSL in the SMTP transaction for dispatching notifications. Turned _off_ by default.
+ **$NotificationsRelayWithCredential** -- Are credentials being used to relay email through the target SMTP server? Turned _off_ by default.
  + **IMPORTANT**: If this is set to `$True` then the script must use the `-SmtpCredential` parameter with a PowerShell credentials object passed to it.
  + See the `Examples` section of this README document below for more information on how to pass credentials to this script.
+ **$NotificationsServer** -- A target server used to relay emails to their destination. This is _required_ to send notifications.
+ **$NotificationsServerPort** -- The relay server's target port.
+ **$NotificationOnNoChange** -- If set, will generate a notification even if there wasn't a change detected across the clients.
  + **$NotificationsBodyOnNoChange** -- Body template for notifications informing of no changes.
+ **$NotificationsAsHTML** -- Whether or not to send emails with HTML formatting. If set to `$False` email notifications will be sent in plaintext.
  + The "class" variables in this section are really not important unless the name is clashing with another CSS class you write or use in the notifications.
+ **$NotificationsHTMLBackgroundColors** -- The two hexadecimal colors to alternate between when switching between clients in the _HTML_ notification.
  + The "$True" boolean value field is **always** _used for the first client_ in the generated notification.
+ **$NotificationsStripHeaders** -- Whether or not to strip out redundant table headers in each category. _Turned off_ by default.
  + **$NotificationsHTMLWrapper** -- The HTML notification wrapper format, including all content between the `<HTML>` tags. The `[[BODYTEXT]]` item here is later replaced with the generated body of the notification.
+ **$NotificationsChangesBodyHeader** -- The header/upper section used in notifications that _will_ have some changes noted for clients.
  + The actual Body text is appended to this value _later_, forming the `[[BODYTEXT]]` piece to either `(a)` fit inside the **HTML wrapper variable**, or `(b)` be inserted as plaintext into the notification.
+ **$NotificationsTriggers** -- Turn on/off delta detections for the listed sections or items. If set to `$False`, the notification will not include change information about the given section.
  + _ReachabilityChange_ : Notify when the reachability of the target host changed (both a ping test and `Invoke-Command` test for WinRM).
  + _InstalledAppsChange_ : Notify when installed applications change.
  + _ServicesChange_ : Notify when services change.
  + _StoreAppsChange_ : Notify when store applications change.
  + _StartupAppsChange_ : Notify when applications run at system startup change.
  + _ScheduledTasksChange_ : Notify when the scheduled tasks of a system are modified.
+ **$NotificationsFilters** -- Define strings (_wildcards supported_) which should be white/black-listed for allowance into notifications. The strings are **arrays** of patterns. For example: `@("win*","*micro*")` will filter anything starting with `"win"` and anything containing the substring `"micro"`. Sub-field names are pretty self-explanatory.
  + These filters apply to **ALL data fields** in the category and should be used with caution. If a service changes from "Group Policy Service" to "Microsoft GPO Svc" for example, and there's a `"micro*"` filter, you won't know about the change.
  + Despite having a notification filter in place, if using the `DeltasReport` parameter, deltas that were filtered out _can_ still be viewed within the generated Deltas Report, which is handy for troubleshooting.
  + **$NotificationsShowFilteredItem** -- _**Off** by default_. Whether or not to show the text of the below variable in the generated notification, when an item is filtered out.
  + **$NotificationsFiltersBlacklist** -- Is the filter a blacklist (default is yes)? If so, anything added to the below object in the target sections is selectively *FILTERED OUT*. Conversely, if set to `$False` then only the given values/patterns will be allowed (thus acting as a whitelist).
  + **$NotificationsFilteredIndicator** -- A string (HTML formatting optional) to insert when an item is filtered from a notification, if the above value is `$True`.
  + **$NotificationFiltersRegex** -- _False by default_. Set the mode for filtering to **regex** instead of wildcard. This will cause the strings entered as filters to be run against the PowerShell `-Match` operator rather than the `-Like` operator. Consider this setting "advanced" and **do not** change this unless you'd like to use regex filtering instead.
+ **$NotificationsRecentInstallationsFiltering** -- When a notification includes deltas of InstalledApps that have *"DisplayVersion"* changes only, append the _specific version and corresponding DisplayName_ to a destination tracker file, and automatically add it to the "Changed" section of the **$NotificationsFilters.InstalledApps.Changed** object.
  + For this to work, _$TrackedValues_ **MUST** include both "DisplayName" and "DisplayVersion". Otherwise, these variables are ignored.
+ **$NotificationsRecentInstallationsAutoTrack** -- If True (and above is enabled), the script will automatically track/index InstalledApps version changes in the destination file.
+ **$NotificationsRecentInstallationsReportLoc** -- The full path of the file to read/write for Recent Installations tracking.
  + By default, this is placed in the Reports Directory with a static filename.
+ **$FilenameTracking** -- Enable/Disable filename tracking on the clients. This allows for greater control over environment monitoring, if desired.
  + **$TrackedFilenameViewLimit** -- How many files to show in the "_most recent_" view in the emailed notification/report. This just presents a sample list of the most recently modified files matching the given pattern, up to the limit set. Recommended max of 20.
  + **$TrackedFilenameLocations** -- Define which places on the target machine's disk should be checked. These are the predefined locations that should be used with caution if the target machine is not the direct localhost.
    + _UserProfiles_ : Uses all directories in the **Users** folder, typically `C:\Users`, and iterates on a per-user basis.
    + _SystemFiles_ : **NOT RECOMMENDED!** Uses `%SYSTEMROOT%`, i.e. `C:\Windows` in most cases, and iterating this directory recursively can take a very long time. You would be better suited to defining either non-recursive or more specific directories in the "custom" variable below.
    + _ProgramData_ : **NOT RECOMMENDED!** Uses `%ProgramData%`, i.e. `C:\ProgramData` in most cases. See above for how to use in a more appropriate way.
  + **$TrackedFilenameLocationsCustom** -- Custom directories to check for certain filename patterns. Key/Value pairs are `[DIRECTORY] = [RECURSE?]` respectively.
    +  _Example_: setting `'C:\Windows' = $True` in the object would order the script to _RECURSIVELY_ check `C:\Windows` for the filename patterns given. Not recommended to do a recursive search in most cases, but just an example.
  + **$TrackedFilenamePatterns** -- The filename patterns (_regex_) to track across all of the above directories, and the associated "threshold". Note that these regexes allow you full control and are _NOT_ restricted to just filename extension.
    + Keypair/Hashtable format: `'[REGEX]' = [THRESHOLD]`
    + Take care with this, as entering `.exe` for example will pick up the filename `processexecute.txt` because the regex isn't specifying the `^` or `$` characters (`line-start` and `line-end` respectively) and isn't escaping the `.` (wildcard) character. Thus, the substring `sexe` matches the pattern in this case.
    + The threshold is the minimum difference at which the delta (of the total files matching the given expression) will be included in the report. For example, a threshold of `10` means that if 10 **MORE** files than the last check are detected, then it should be rolled into the notification for changes on that client.

---

## Notifications
Notifications are designed to be generated to a target SMTP relay server (using the config file), and can have either plaintext or HTML formatting. Here is a sample notification from a simple _LOCALHOST_ differentiation in a few monitored locations.

A couple things to note with notifications like this:
- The actual values under the changed _Client License Service_ that were changed are highlighted as bold and italic simultaneously.
- Some fields may show up completely empty. This almost always indicates a **null value** was in that field. But typically the script will insert a `null` string into the box instead.
- This format can be entirely controlled/restyled within the _configuration file_, as mentioned above.

![Sample Notification from the Monitoring Script](https://raw.githubusercontent.com/NotsoanoNimus/client-monitor/master/docs/Notification_Sample.png)

---

## Examples
Below are a couple of examples using the `Parameters` explained at the beginning of this document, to achieve certain functions that may be desirable.
Keep in mind that regardless of the options you choose to implement as the administrator, the script is designed to be run as a **scheduled task**, so the first example might only be very useful for first-time use or for troubleshooting.

+ `$deltas = .\Client-Monitor.ps1 -NoNotifications -NoMini -DeltasReport`
  + Suppresses any email notifications that would ordinarily be generated.
  + Keeps all generated reports for each client in a readable _JSON_ format (trading disk space for readability).
  + Generates a Deltas Report in the `$ReportsDirectory` location given to the script.
  + `$deltas` is set to a return variable from the script, equal to the object output in _JSON_ format in the Deltas Report.
+ `.\Client-Monitor.ps1 -ClientsList "C:\target-clients.txt" -BCC "target@testing.com, Notsoano Nimus <postmaster@thestraightpath.email>"`
  + Use the clients list at `C:\target-clients.txt` to target specific IP addresses or hostnames on the network. This text file could also include just `LOCALHOST` if it is desired for the script to monitor **only** the host machine.
  + Silently send a copy of the notification email to both of the _BCC_ addresses given (notice they're comma-separated).
+ `.\Client-Monitor.ps1 -BCC "silentnotification@test.com" -DeltasReport -SmtpCredential $creds`
  + Relays with authentication (using the Configuration File variables) to both the destination email address and silently to the BCC address.
  + `$creds` is an object set earlier before the task was run. Usually like so: `$creds = Get-Credential` and then filling out the SMTP credentials in the pop-up window.
    + `$creds` can also be replaced by a manual instantiation of a PSCredentials object, if you're comfortable with having a username/password combo in plaintext: `(New-Object PSCredential ('user@domain.com', (ConvertTo-SecureString 'secretRelayPassword' -AsPlainText -Force)))`.
  + Additionally, `-DeltasReport` generates the Deltas Report if needed by the administrator.

---

## TODOs
- [X] If filters are engaged and _NOTHING_ is in the report except a few blank sections (because things were filtered out), appropriately send the "No Changes" email to indicate that no **tracked changes** were discovered.
- [X] Make compared & selected fields from each category (StoreApps, Services, etc) dynamic using a single config variable. Basically allow a single config to define which fields are discovered and compared among the categories.
- [X] Add some form of SMTP relay using authentication, perhaps with `Get-Credential`. Haven't looked into this too much yet.
- _(?)_ Add a way to dynamically change the indexing format used for keying certain values.
- Update documentation and _docs_ folder with some client-monitor example environments.
- [ ] **IMPORTANT**: Notification filters _FAIL_ when being applied to ARRAYS OF OBJECTS. So if a certain key/value pair in any fetched information returns multiple table entries, the notification filters will not apply to them. There are **two** possible fixes:
  - [ ] Within the notifications filter, split the array if it is indeed an array,
  - [X] _AND/OR_ Ensure that the indexing variable name is always unique.
- [ ] Fix up a lot of the filename tracking contexts and ensure their integrities.
  - This is becoming more of an issue as the rest of the monitor becomes cleaner.
- [X] Consider offloading the _Tweaks_ section to a **separate** configuration file.
  - Though this could interfere with script signing, it works well for administrators to get constant Client Monitor script updates without constantly having to copy-paste their config over my defaults.
- [ ] **Done to a minor degree** Fix the table output sorting (columns will get skewed in the notification output between similar items).
- [ ] Perhaps make filtering conditional or more specific, maybe based on the key/value pairs. Having a plain regex for the _whole_ table makes it a pain sometimes to guarantee that the regex won't mistakenly filter something that might be malicious.
