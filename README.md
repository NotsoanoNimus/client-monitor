# Client-Monitor
A PowerShell script to monitor a client environment for changes from a central administrative server by leveraging the power of Windows Remote Management, generating reports and email notifications to present each detected change per workstation/client.

Here is a sample notification produced by the monitor on my local desktop (ca. 2020-01-03):

![A sample Client Monitor notification from my local desktop.](https://raw.githubusercontent.com/NotsoanoNimus/client-monitor/master/docs/CliMon_v2.png)

**NOTE**: The timer for this scheduled run was due to the heavy amount of _filename tracking_ being done across my machine, as well as _full verbosity_ debugging output for logging.


# Requirements
- A Windows desktop or server environment as the _head_ machine running the monitor.
- Other machines/clients to monitor, if you're not just monitoring yourself.
- PowerShell **version 5** or beyond, preferably on **BOTH the head and the targets** but the _head_ might be the only one needing v5+.
  - If you'd like to use Client Monitor but (for some reason) don't have access to PowerShell 5+, or if the current version isn't working, you can elect to use the **Legacy** Client Monitor as described in the bottom section of this document.
- Decent hardware. From testing, it seems that the script gobbles up quite a bit of resources, but I have no specifics.
  - Chances are, if you're running PowerShell v5+ and you're not simultaenously expending all resources, you won't have a problem.
- _Optional._ Knowledge of Windows Task Scheduling and how to set up a new job, to automate runs of Client Monitor.


# Tutorial / Getting Started
See [this document](https://github.com/NotsoanoNimus/client-monitor/blob/master/docs/HOWTO.md) for getting the project set up, and for command-line parameters you can use.


# Features
Client Monitor, being yet another FOSS solution to address a widely-requested administrative feature, sports a growing amount of features that can be toggled based on values _predefined within the configuration file_ that comes with the project.

### What Information Can Be Tracked?
Here is a list that describes each category and property you can expect to monitor (as enabled). The Sub-Categories in _italics_ can be changed at-will within the Client Monitor configuration file.
+ **Reachability Status**: Whether or not the computer is (1) pingable and (2) invokable over the WinRM service. If either of the two tests fail, the client is considered 'unreachable' and will be effectively ignored for the rest of the run.
+ **IP Address Subnet Membership**: The membership of a client IP address, or set of addresses, to a predefined _block of subnets_.
+ **Installed Applications**: Any 'application' that registers itself with a valid uninstaller in the Windows registry. This includes the HKCU/HKU/HKLM hives, in multiple locations therein.
  - _DisplayName_, _DisplayVersion_, _Publisher_, _InstallDate_, and _InstallLocation_.
  - Though this doesn't solve the tracking necessity for plain, stand-alone `.exe` or `.cmd` files/scripts, the `filename pattern tracking` feature may be of interest to track such extensions. :)
+ **Services**: System services that are currently registered (in any state or start-type).
  - _DisplayName_, _ServiceName_, and _StartType_.
+ **Store Apps**: Any Windows store app (for any user), registered under the `Get-AppxPackage -AllUsers` cmdlet call.
  - _Name_, _Architecture_, _InstallLocation_, _Status_, _PublisherId_, and _PackageFullName_.
  - This section includes the **non-modifiable** property: _PackageUserInformation_.
+ **Startup Apps**: Any startup application registered in the system registry, in either a per-user or per-machine location.
  - _Command_, _Location_, and _User_.
+ **Scheduled Tasks**: Jobs and scheduled tasks registered on the target system.
  - _TaskName_, _TaskPath_, _Author_, and _SecurityDescriptor_
+ **Filename Patterns (Counts)**: Counts the amount of files in a given location below that both (1) match a _configuration-defined regex pattern_ and (2) exceed a corresponding _count threshold of matched files_ between CliMon reports/runs. See the configuration for more information on how this works!
  - _User Profiles_: Recursively check the user-profile location on a machine -- typically `C:\Users\` -- for matching files.
  - _Program Data_: Recurseively check the ProgramData location -- typically `C:\ProgramData\` -- for matching files.
  - _System Root_: Recursively check the Windows system directory -- typically `C:\Windows\` -- for matching files.
  - _Custom Locations_: A directory to check on the target clients for the matching patterns. The configuration file specifies whether or not you'd like this to be a recursive check, or a single-level check, with a boolean value.

The five major categories (InstalledApps, Services, StoreApps, StartupApps, & ScheduledTasks) are always reported as one of three "delta" types: **New**, **Removed**, or **Changed**.

### What Else Does It Do?
The following features are included with the CliMon project, so long as the **configuration marks them** as _Enabled = $True_, where applicable:
+ **Honing**: Users or clients can be specifically targeted in two ways: 
  - **Active Directory**: The `DomainUserFilter` configuration variable or alternative parameter can be used to specifically select pools of hostnames to monitor from the directory.
  - **Clients List**: Feeding the script a list of client hostnames and IPs (or a mix thereof) will also cause the script to only target the valid hosts from the list. This can only be used with the `ClientsList` command-line parameter, and is explained in further detail in the How-To document.
+ **Failure/Fault detection and protection**: If the Client Monitor traps a critical, fatal error for _any_ reason during the run of the script, it will use the pre-configured SMTP settings to generate a notification with information related to the crash (and also to let someone know it failed). Additionally, when the monitor crashes for any reason, _the reports generated during the run are rolled back_ since a valid notification failed to dispatch due to the failure. Which brings us to the next feature...
+ **Rollback Options**: By default, the Monitor is designed to roll back any client information from selected (or all) targets in the following scenarios: the Ephemeral parameter is set, a client session dies in the middle of the surveillance, or the script experiences a fatal crash.
+ **Session Management**: The Monitor keeps a watchful eye on its targets as it collects information. Between each remote invocation, if a session is broken an assertion will be given, and if that fails to re-establish the session then the client is marked as "Dead" to be included in the notification's _rarely-seen_ "Dead Sessions" section. As mentioned above, the client's report files will also be rolled back to the last known successful collection of data.
+ **One-and-Done Approach**: The Monitor is designed to finish the information gathering all in one single burst of network activity. This is a recent development -- thanks to the session management feature -- that only requires a short window for sessions to be maintained and reported.
+ **Per-User Tracking**: All `NTUSER.DAT` registry files are mounted and read from a "shadow" directory by the script, so that even _user-specific_ startup applications or desktop applications can be monitored.
+ **Notification Customization**: For the most part, the entire notification can be customized to provide the both style and information that you prefer.
+ **SMTP Settings**: All SMTP settings can be customized to ensure delivery of the notification appropriately to its intended destination, with the right information.
+ **Snapshots**: Use the "SnapshotMode" parameter to collect **all** information about the given targets at any time. This is an incredibly useful "spot-check" to double 
  - Can be combined with "NoFilters" to generate a completely unfiltered query of all information about the targeted client(s).
  - Combining with adjustments to the _Notifications Triggers_ section of the config allows only specific items to be collected in the snapshot.
+ **Selective Filtering**: The window for creativity with these is massive! Information matching certain patterns (regex or wildcard-based depending on the configuration) can be either whitelisted or blacklisted into the final notification. This is _very_ useful for filtering things that consistently show up, or things that you don't care to monitor, and helps to fight alert fatigue.
  - A great example is filtering the Publisher ID for Windows Store Apps, like Skype and Xbox items.
  - Another helpful use of blacklist filtering is getting rid of 'noise' like changing service ID hashes from system services.
  - Whitelist filtering can be used in combination with either "Snapshot Mode" or "Ephemeral" to collect information about _only certain items_ and leave everything else out of the report.
  - Filters can also be _disabled entirely_ without the need to remove any configuration customizations, by using the command-line parameter "NoFilters" to suppress them.
  - You can set the notifications to include a snippet about the "count" of filtered items from each section, if desired.
+ **Timing**: The script itself is monitored for its run-time from start-to-finish, and then adds that information to the notification along with a count of the valid clients that were scanned. This is excellent for benchmarking the script.
+ **Debugging**: The option to "debug" the script is exceedingly helpful for resolving issues, and even more valuable for reporting any issues that may need to be addressed as a bug-fix. **Beware: this causes MASSIVE increases in script runtime due to all the output it produces.**

And much more that gets added with each commit.

### How Can I Interpret or Implement CliMon Information/Results?
This section is aimed to address questions like: "My email client is awful with HTML rendering. Can I receive the notification as an attachment instead?" or "Are there any other data formats I can sift through quickly?", or even "Can I view any of the intermediate data?"

The answer to all of these questions is _yes_. See below for the (growing) list of methods you can use to browse the Client Monitor information:
+ Notifications as HTML attachments instead of within the message body, by using the "AsAttachment" command-line parameter.
+ Import the "REPORT" JSON files into a viewer of your choice. Even a web browser can work for this.
  + I am planning to write a document outlining how the Client Monitor REPORTS and Deltas Reports format can be better understood, but it's rather legible on its own for the most part, so that is low-priority at this time.
+ Generate a "Deltas Report" file for each run which will include a combined JSON object that shows the **completely unfiltered** list of all differences detected in the client environment. This is useful for capturing things you may have mistakenly filtered, or just watching things you want to filter from the final report anyhow.
+ Use the _FlatReportCsv_ parameter to generate (and if configured, attach to the notification) a CSV with all _unfiltered_ information that's been collected from the client environment. 
+ _Plain-Text Results_. That's right, you can get a rudimentary bastard-child plain-text file from the monitor instead of an HTML file, if you're crazy enough. And yes, it can be sent as an attachment too if desired.
+ JSON files can either be compressed (minified, with no whitespace), or expanded into a "pretty" view by default that's much more human-readable. This includes both the REPORTS and Deltas Reports files.


# Project Flow
The Client Monitor project has a very distinct and procedural method for completing its report generation, data comparisons, and notification handling. Below is an infographic that describes this flow in a digestable manner.

_Image coming whenever I get around to making it._ For now, just viewing the `Invoke-MainRoutine` in the main `Client-Monitor.ps1` file will provide plenty of the high-view information you seek.


# Legacy Client-Monitor
The "legacy" Client Monitor can be found in the packaged **Legacy (1.0)** folder (with its README file), and is considered a _last-resort_ rendition of the script, if by any means a user cannot get the current version to function, _or if a user doesn't use PowerShell v5+_.

Though it built what the project is today, Legacy is a mostly-single-file script doing all of what Client Monitor does now in a sloppy and primitive way. The code, for obvious reasons, is not very maintainable or stable. Thus, it's been shelved in favor of the new "modularized" version of Client Monitor, the complexity of which is eased by its new ability to be adjusted/fixed quickly.