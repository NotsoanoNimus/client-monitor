# Things TODO
This file lists all non-critical plans for the project going forward. Any issues or critical problems should be separately created and noted as a GitHub "Issue" so it can be properly tracked and fixed promptly.

### Queued (non-issue) Changes
- [ ] Certify and digitally sign the PowerShell scripts.
- [ ] IPv6 client support.
- [ ] Add `Write-Debug` calls to the methods for the `CliMonClient` module class to provide much better transparency. Also add them within the class definition of `CliMonNotification`.
- [ ] Improve the information provided by the different Debug thresholds.
- [ ] Information limitation. Runs of Client Monitor (particularly the "new" version) have not been tested in environments where the clients list is greater than about 60 targets or so.
  - The fear is that too many clients may cause excess resource usage, and thus a crash or gross miscalculation, based on all of the large data permutations being performed and collected into objects -- particularly piped or chained commands.
  - This could perhaps be implemented in a "step-by-step" client parsing method: the script could run through a batch of 20 targets at a time for a whole "data cycle", then circle back to the top of the Main function, but with 20 more targets, _ad infinitum_ until the targets list is exhausted.
- [X] More **asynchronous tasking**. Commands to client sessions can be run simultaneously, which could greatly improve the speed of the script during the "Gathering" stage when data is being collected.

And of course: send suggestions and report any bugs you come across! I'd be happy to take them.

### "Version 3" Ideas
This section is really just a scratchpad of ideas that could be implemented much later. They are separate from the "TODO" section because they are only ideas that are being "set on the table", _not_ items that are active, queued, or pending.
- Maintain a constant session state with clients. Combine asynchronous processing with the newly-added "sessions" for clients to keep the sessions open and constantly monitor the clients.
  - At a specified interval (e.g. every 5 minutes), the script could run a check on the client and look for deltas. If any changes were found, the time of the change and the delta itself could be added to an object attribute in the `CliMonClient` object's instance for that target.
  - This would prevent one of the **biggest flaws** in the current rendition of Client Monitor: _report gapping_.
    - Suppose your schedule was every 4 hours to run the monitor: 0000 - 0400 - 0800 - 1200 - 1600 - 2000
    - In this circumstance, if I'm wise to your schedule, I could install something potentially unwanted at 1230 and as long as it's gone by 1600 then it would never show up in the Client Monitor notification to the administrator(s).
  - A problem: this generates a LOT of HTTPS traffic over WinRM.
  - Another problem: finding the "sweet spot" for check intervals. An environment that's very large may have checks collide if the interval is set too short.
    - Perhaps this could be remedied with a `lock` sort of setup. Some cheap global Boolean that the script can check to see if there's already an environment check pending.