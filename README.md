# Client-Monitor
A PowerShell script to monitor a client environment for changes (filename patterns, services, startup applications, store apps, scheduled tasks, & installed apps) from a central administrative server, generating reports to view each change per workstation/client.


# Requirements
- A Windows desktop or server environment as the _head_ machine running the monitor.
- Other machines/clients to monitor, if you're not just monitoring yourself.
- PowerShell **version 5** or beyond, preferably on **BOTH the head and the targets** but the _head_ might be the only one needing v5+.
  - If you'd like to use Client Monitor but (for some reason) don't have access to PowerShell 5+, or if the current version isn't working, you can elect to use the **Legacy** Client Monitor as described in the bottom section.
- Decent hardware. From testing, it seems that the script gobbles up quite a bit of resources, but I have no specifics.
  - Chances are, if you're running PowerShell v5+ and you're not simultaenously expending all resources, you won't have a problem.
- _Optional._ Knowledge of Windows Task Scheduling and how to set up a new job, to automate runs of Client Monitor.


# How to Use It
Simple! The new version of Client Monitor comes prepackaged with a very simple _.bat_ file you can use to run the monitor while also capturing its output. You can modify this file to also run other pre- and post-script tasks. It's best advised to put the `monitor.bat` file as the "Action" in Windows task scheduler if you're going to use this tool as a scheduled monitor.

### Take Ownership
**IMPORTANT**: If you don't do this, the script will _not work_ on your machine!

Before using any of the PowerShell scripts, please **open your own PowerShell window** -- _{WindowsKey+R}, powershell, {ENTER}_ -- and enter the following command:
```
(Get-ChildItem -Path "C:\the\directory\of\clientmonitor\" -Recurse -File `
| where Name -Match '\.psm?1$').FullName | % { Unblock-File -Path $_ }
```
The files should now be **unblocked** from running on your machine. By default, they are blocked since they'll have come from the untrustworthy internet, and as of right now do not have a valid digital signature.

This step is going to be required until I get around to digitally verifying and signing the Client Monitor script, at which point this section of the _how-to_ will be removed.

### Ready the Target Clients
If the scanned clients include others outside of just your local machine, which will be the case for most users, you'll want to pre-configure each client to accept remote invocations for PowerShell with the **WinRM** service. [You should read more about this.](https://www.pcwdld.com/what-is-winrm)

Lest the script determine that the targets are "not invokable" and thus un-monitorable, the target clients will:
- Need to be reachable on **ports 5985 and 5986** for HTTPS traffic.
- Need the **WinRM service** to be enabled and running.

You can make these changes either via a Group Policy change, or manually, depending on your environment. This part is up to you to figure out.

**Using a ClientsList Option**
The `ClientsList` parameter is an _optional_ script parameter, as described in the below section, which allows a user to "feed" Client Monitor a line-by-line file of target client hostnames, IPv4 addresses, or a mix of the two. This is an example of a "Clients List" file:
```
127.0.0.1
thisisa-badclient#@@hostname#$@@@^&* :))):):):)
DESKTOP5.WORK.LOCAL
192.168.78.87
FRONTDESK1
2001:db8:1000::12
```
This will scan all **valid** hostnames or IPv4 addresses from the list above (i.e. `127.0.0.1`, `DESKTOP5.WORK.LOCAL`, `192.168.78.87`, and `FRONTDESK1`), provided they are `online` and `invokable` over **WinRM** as required by the previous step. It will also ignore "invalid" targets as the script runs, so mistaken lines or comments are trivial.

Please note that IPv6 clients are currently not supported at this time, but is on the to-do list and will be added once tested.

**Using Microsoft Active Directory (MSAD)**
Client Monitor also makes effective use of the Active Directory module cmdlet `Get-ADComputer` to get a list of client hostnames within your directory. The returned list is then further filtered and narrowed based on the value you configure in the next section for the `DomainUserFilter` configuration variable.

Keep in mind that `DomainUserFilter` can also be manually added to the script as a command-line parameter, to override the configuration. This is very useful when running an ephemeral view against a certain client or group of the regular targets to get their recent changes without changing anything, for example.

### Make Configuration Changes
Once you've figured out how you're going to name your targets, and that they're reachable with WinRM, it's time to give Client Monitor a valid configuration to use (tailored to your use-case).

The configuration file is extremely detailed for each option available! Head on over to the `Client-MonitorConfig.ps1` file to examine your configuration options (which are _required_ for the script to work), and be sure that everything is configured as you'd like it before proceeding.

_Please_ pay attention to these configuration variables, as a slight misstep can have unintended consequences!

### Run it!
The below is an **example** of manually running the script from the PowerShell CLI with certain parameters (noted in the next section):
```
C:\Client-Monitor> .\Client-Monitor.ps1 -ClientsList ".\clients.txt" -AsAttachment -Ephemeral [... any other params ...]
```
Alternatively, you can modify the `monitor.bat` file to your liking and use it to capture terminal output. This also works great for creating a scheduled tasks with the Windows scheduler, so you can run this regularly and automatically. I personally do this, and run it on my local machine every morning.

That's all there is to it!

See the **Parameters** section shortly below for more information on valid Client Monitor parameters to change its behavior to your liking.


# Parameters
This is a direct copy from the `Get-Help` helper at the top of `Client-Monitor.ps1` but may be embellished with more helpful information.

### Debug
Optional. Debug the script as it runs. 1 = Least verbose // 4 = Most verbose.
### ClientsList
Optional. The path to a line-delimited file of IPs/hostnames to target as reported clients.
### DeltasReport
Optional. If included as a switch to the script, a DELTAS text file will be generated in the reports directory.
This will only happen if deltas were actually detected across the target clients since the last report.
### NoNotifications
Optional. If included as a switch to the script, the script will NOT send email notifications at all.
### BCC
Optional. If included, will BCC the target address(es) in the generated notifications. An example usage might be 
something like: `-BCC "Admin One <admin1@corp.net>","Alphabet Two <glow@alphabet.corp>"
### NoMini
Optional. If included, the reports generated by the script will NOT be compress/mini-fied, so they become more readable.
### DomainUserFilter
Optional. If included, allows a manual override of the configuration variable for DomainUserFilter, where
a specific workstation or other PowerShell conditional (or groups of conditionals) can be inserted.
This will have no effect on Client Monitor instances using the ClientsList parameter, as it is specific
to the Get-ADComputer command.
It is useful for a one-time run targeting a specific set of the user domain.
### SnapshotMode
Optional. If included as a switch, the notifications generated by the script will be generated as
if the script is being run for the first time. It is a way to collect all current information in the
client environment. When used with the NoFilters switch, it will display a COMPLETE and UNFILTERED view
of the client environment (i.e. all collected data) in a single notification.
SPECIAL NOTE: Using SnapshotMode will NOT override the "Notification Triggers" section, so there is
still a possibility for an end-user to sieve only the information s/he wants.
### NoFilters
Optional. If included as a switch, the script will not apply any of the filters present in the
configuration to the generated email notification. It is best used in combination when generating a
report of ALL collected information is desired (with the SnapshotMode switch).
### AsAttachment
Optional. Send the HTML/plaintext generated by the report as an attachment instead of inline HTML.
### FlatReportCsv
Optional. Create a flat CSV report of all client information, using all columns from the TrackedValues.
This is useful to open the Client Monitor results in something like Excel, for easy sorting/navigation.
### Ephemeral
Optional. If included, run the script in a mode that does not generate any incremental reports. Meaning,
the monitor will not save report states or tracking updates, and will only serve to run as a deltas test
from the last set of reports, without actually updating anything.
### ConfigFile
Optional. Defaults to ".\Client-MonitorConfig.ps1", but can be the full path of a Client Monitor configuration file.
### SmtpCredential
Optional. Manually override any PSCredential object defined in the configuration for SMTP relays.


# Benchmarking
This section will be given more information as time goes on. However, it's worth nothing here in the README that the **average per-client processing time** for a _non-first-time run_ (and when _not_ debugging) seems to average approximately `12 seconds` over fiber connections in a LAN. This is a significant improvement over the former speed, which was about _34 seconds_ when last measured during the "Legacy" version.

The average time is calculated simply as the time from start-to-finish ("finish" being the end of notification generation), divided by the number of target clients to scan in the environment. Because of this, the more deltas that are tracked throughout the script's session, the longer the processing time will become. This means that the presented average is heavily biased towards a **no-deltas-reported** sort of scenario, meaning that very few, if any, deltas were detected by the monitor -- therefore very little time is spent on comparisons and notification generation.

Recently, the script has been given the ability to provide two valuable pieces of information in the final report (if configured):
- The total runtime of the script.
- The number of _valid_ clients being processed.


# Things TODO
- [ ] Certify and digitally sign the PowerShell scripts.
- [ ] IPv6 client support.
- [ ] Add `Write-Debug` calls to the methods for the `CliMonClient` module class to provide much better transparency. Also add them within the class definition of `CliMonNotification`.
- [ ] Information limitation. Runs of Client Monitor (particularly the "new" version) have not been tested in environments where the clients list is greater than about 60 targets or so.
  - The fear is that too many clients may cause excess resource usage, and thus a crash or gross miscalculation, based on all of the large data permutations being performed and collected into objects -- particularly piped or chained commands.
  - This could perhaps be implemented in a "step-by-step" client parsing method: the script could run through a batch of 20 targets at a time for a whole "data cycle", then circle back to the top of the Main function, but with 20 more targets, _ad infinitum_ until the targets list is exhausted.
- [ ] More **asynchronous tasking**. Commands to client sessions can be run simultaneously, which could greatly improve the speed of the script during the "Gathering" stage when data is being collected.

And of course: send suggestions and report any bugs you come across! I'd be happy to take them.

### "Version 3" Ideas
This section is really just a scratchpad of ideas that could be implemented much later. They are separate from the "TODO" section because they are only ideas that are being prodded, _not_ items that are active, queued, or pending.
- Maintain a constant session state with clients. Combine asynchronous processing with the newly-added "sessions" for clients to keep the sessions open and constantly monitor the clients.
  - At a specified interval (e.g. every 5 minutes), the script could run a check on the client and look for deltas. If any changes were found, the time of the change and the delta itself could be added to an object attribute in the `CliMonClient` object's instance for that target.
  - This would prevent one of the **biggest flaws** in the current rendition of Client Monitor: _report gapping_.
    - Suppose your schedule was every 4 hours to run the monitor: 0000 - 0400 - 0800 - 1200 - 1600 - 2000
    - In this circumstance, if I'm wise to your schedule, I could install something potentially unwanted at 1230 and as long as it's gone by 1600 then it would never show up in the Client Monitor notification to the administrator(s).
  - A problem: this generates a LOT of HTTPS traffic over WinRM.
  - Another problem: finding the "sweet spot" for check intervals. An environment that's very large may have checks collide if the interval is set too short.
    - Perhaps this could be remedied with a `lock` sort of setup. Some cheap global Boolean that the script can check to see if there's already an environment check pending.


# Project Flow
The Client Monitor project has a very distinct and procedural method for completing its report generation, data comparisons, and notification handling. Below is an infographic that describes this flow in a digestable manner.

_Image coming whenever I get around to making it._ For now, just viewing the `Invoke-MainRoutine` will provide plenty of high-view information.


# Legacy Client-Monitor
The "legacy" Client Monitor can be found in the packaged **Legacy (1.0)** folder (with its README file), and is considered a _last-resort_ rendition of the script, if by any means a user cannot get the current version to function, _or if a user doesn't use PowerShell v5+_.

Though it built what the project is today, Legacy is a mostly-single-file script doing all of what Client Monitor does now. The code, for obvious reasons, is not very maintainable or stable. Thus, it's been shelved in favor of the new "modularized" version of Client Monitor.