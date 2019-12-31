<#
 # CliMonClient.ps1
 #
 # Define the core component of Client Monitor: a CliMonClient object, which will hold
 #  all validations necessary to ensure valid clients are given, and that sessions can
 #  be safely managed.
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



# Regexes to use for client matching and info gathering during object construction.
#  NOTE: The TLD section of HOSTNAME_WITH_SUFFIX should include - and _ just in case COMPUTERNAME is used
#         as a DomainName configuration variable when the field is left blank.
$global:ClientMonitorRegexes = @{
    'HOSTNAME' = '^(?!\d+$)[a-zA-Z0-9\-_\\]+$';
    'HOSTNAME_WITH_SUFFIX' = '^[a-zA-Z0-9][a-zA-Z0-9\._\-]+\.[a-z0-9\-_]{2,}$';
    'LOCALHOST_HOSTNAME' = "^(LOCALHOST([0-9]|\.localdomain)?|$([Regex]::Escape($env:COMPUTERNAME)))$";
    'IPV4_ADDRESS' = '\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4}\b';
    'SID' = '^S-\d+-\d+-\d+-';
}


# A "client" model to use and reference for each individual network client.
#  This model manages everything for a single client, including information retention and session management.
Class CliMonClient {
    [String]$Hostname = $null   #the client's hostname (capitalized, with the DomainSuffix variable added)
    [String]$IpAddress = $null   #the client's ipv4 address
    [String]$Ip6Address = $null   #the client's ipv6 address (if any) -- this is scaffolding for later
    [String]$RealName = ""   #the full (or partial) name of the workstation
    [Boolean]$IsValid = $False   #is the object a 'valid' client (has all needed info)
    [Boolean]$SessionOpen = $False   #is the session currently open
    [System.Management.Automation.Runspaces.PSSession]$ClientSession = $null

    # Tracked values captured during the "GatherInformation" part of the script.
    $Profile = [Ordered]@{
        IsOnline = $False; IsInvokable = $False;
        OnlineStatusChange = $False; InvokableStatusChange = $False;
        FilenameTrackers = @{}; FilenameTrackersPatterns = @();
        InstalledApps = @{}; InstalledAppsIndex = @();
        StoreApps = @{}; StoreAppsIndex = @();
        StartupApps = @{}; StartupAppsIndex = @();
        Services = @{}; ServicesIndex = @();
        ScheduledTasks = @{}; ScheduledTasksIndex = @();
    }

    # Default (and only) constructor method.
    CliMonClient([String]$initialParam) {
        # Pre-filter anything prefixed by one or two backslashes. Just strip it out.
        $initialParam = $initialParam -Replace '^\\{1,2}'
        # If the initial parameter matches a localhost-type hostname, set the hostname to either the
        #  COMPUTERNAME environment variable, or to 'localdomain', depending on the global domain suffix.
        # If a suffix is configured that's NOT localdomain, the COMPUTERNAME variable is likely to work best.
        if($initialParam -imatch $global:ClientMonitorRegexes['LOCALHOST_HOSTNAME']) {
            $initialParam = 
                if($global:CliMonConfig.DomainSuffix -eq '.localdomain') { 'localhost' }
                else { "$env:COMPUTERNAME" }
        }
        # This constructor can be fed any string, which will be tested for either a hostname or an IPV4 address.
        #  It will then flesh out the client accordingly.
        $this.Hostname =
            if($initialParam -match $global:ClientMonitorRegexes['HOSTNAME']) {
                ($initialParam + $global:CliMonConfig.DomainSuffix).ToUpper()
            } else { $this.GetHostname($initialParam) }
        $this.IpAddress =
            if($initialParam -match $global:ClientMonitorRegexes['IPV4_ADDRESS']) { $initialParam }
            else { $this.GetIpAddress($initialParam) }
        # Do a validity test and set the property.
        $this.IsValid = $this.GetValidity()
        # If the configuration specifies that a "real name" is desired, fetch it. This requires validity.
        $this.RealName = 
            if($global:CliMonConfig.RealnameTranslation.Enabled -eq $True -And $this.IsValid -eq $True) {
                $this.GetRealName()
            } else { "" }
    }

    # Ensure the attributes of the instantiated object are valid, based on the parameter given to the constructor.
    [Boolean] GetValidity() {
        return (
            $this.Hostname -match $global:ClientMonitorRegexes['HOSTNAME_WITH_SUFFIX'] -And
            $this.IpAddress -match $global:ClientMonitorRegexes['IPV4_ADDRESS']
        )
    }

    # Get an IPV4 address from a hostname.
    [String] GetIpAddress([String]$givenHostname) {
        try {
            # Use the System DNS library to resolve the hostname properly.
            $resolvedAddress = 
                [System.Net.Dns]::GetHostAddresses("$givenHostname").IPAddressToString
        } catch {
            # The hostname couldn't be resolved. Return null to indicate this.
            $resolvedAddress = $null
        }
        # If the amount of returned IPs is greater than 1, this usually implies IPv6 addresses were returned.
        #  This is not desired at this time, so instead fetch the first IPv4 address in the array.
        if($resolvedAddress -Is [Array] -And $resolvedAddress.Length -gt 1) {
            $finalIp = ""
            if($givenHostname -inotmatch $global:ClientMonitorRegexes['LOCALHOST_HOSTNAME']) {
                $resolvedAddress | ForEach-Object {
                    if($_ -match '^[0-9\.]+$' -And $_ -notmatch '^127\.|^22[4-9]\.|^2[3-5][0-9]\.|^169\.254\.') {
                        # Stops at the final match of an actual IP address that isn't 
                        #  127.0.0.0/8, 169.254.0.0/16, or anything beyond 224.0.0.0/8, if and only if the given
                        #  hostname is not equal to the ComputerName variable or 'LOCALHOST'.
                        $finalIp = $_
                    }
                }
            } else {
                # If the hostname actually is a localhost (or COMPUTERNAME) address, simply set the final result
                #  to the loopback IP address. Setting to the local IPv4 LAN address of the local machine usually
                #  won't work if the Windows Firewall doesn't have WinRM enabled. Most users running this reflectively
                #  typically will not have WinRM running, so this safeguards against failure in that scenario.
                $finalIp = '127.0.0.1'
            }
            # The finalIp variable is a nice intermediate variable, just in case overwriting the "address" variable
            #  causes issues while iterating the array.
            $resolvedAddress = $finalIp
            # If no valid IPv4 addresses were extracted, return a null to indicate failure.
            if($finalIp -eq "") { $resolvedAddress = $null }
        }
        return $resolvedAddress
    }
    # Get a hostname from an IPv4 address, using a reverse-DNS lookup.
    [String] GetHostname([String]$ipv4Address) {
        $resolvedHostname = $null
        try {
            # Use the system DNS library to attempt a reverse-DNS check for the IP address.
            $resolvedHostname = [System.Net.Dns]::Resolve("$ipv4Address").HostName
        } catch { }
        # If the hostname was resolved, get its first occurrence (in case it's an array).
        if($resolvedHostname -Is [Array] -And $resolvedHostname.Length -gt 1) {
            $resolvedHostname = $resolvedHostname[0]
        }
        # If the hostname matches an IP Address pattern (which happens on bad lookups), discard it.
        if($resolvedHostname -match $global:ClientMonitorRegexes['IPV4_ADDRESS']) {
            $resolvedHostname = $null
        }
        # If there is not already a domain suffix attached (and target isn't LOCALHOST), bring it in from the config.
        if($resolvedHostname -notmatch $global:CliMonConfig.DomainSuffixRegex -And
          $resolvedHostname -notmatch '^LOCALHOST(\.)?' -And
          $null -ne $resolvedHostname) {
            $resolvedHostname += $global:CliMonConfig.DomainSuffix
        }
        # Final check: as long as the hostname isn't null, capitalize it.
        if($null -ne $resolvedHostname) { $resolvedHostname = $resolvedHostname.ToUpper() }
        # Returns $null if no hostname could be resolved.
        return $resolvedHostname
    }
    # Get the "real name" of the client based on the configuration parameters.
    [String] GetRealName() {
        $local:indexType = $global:CliMonConfig.RealnameTranslation.IndexedBy
        # Get the index value. If there's an incorrect value for the indexType, return an empty string.
        if($local:indexType -eq "Hostname") { $local:indexValue = $this.Hostname }
        elseif($local:indexType -eq "IpAddress") { $local:indexValue = $this.IpAddress }
        else { return "" }
        $local:queryType = $global:CliMonConfig.RealnameTranslation.Method
        if($local:queryType -eq "HTTPRequest") {
            # Get the base URL, attempt to format it, and attempt to run the request.
            $local:baseUrl = $global:CliMonConfig.RealnameTranslation.HTTPRequest.BaseUrl
            try {
                $local:fullUrl = $local:baseUrl -f $local:indexValue
                $local:fetchedName = (New-Object System.Net.WebClient).DownloadString($local:fullUrl)
                # OK to return the fetchedName because an empty string comes back if the request is bad.
                #  If the URL ends up bad or otherwise unreachable, the try/catch should handle it.
                return $local:fetchedName
            } catch { return "" }
        } elseif($local:queryType -eq "DirectObject") {
            # Get the table from the config, search for the key/indexValue, and get the value in the table.
            $local:directTable = $global:CliMonConfig.RealnameTranslation.DirectObject.Table
            $local:fetchedName = $local:directTable."$($local:indexValue)"
            return (if($null -eq $local:fetchedName) { "" } else { $local:fetchedName })
        } else {
            # If there's an invalid query type, return an empty string.
            return ""
        }
    }

    # A boolean function to return whether or not the client is a localhost client.
    [Boolean] IsLocalhost() {
        return ($this.Hostname -ILike "LOCALHOST*" -Or $this.IpAddress -Like "127.*")
    }

    # Runs a command through the client's active session (if any).
    #  success = Returns true when the operation is successful, and false if unsuccessful.
    #  result = The return or result of the remote command.
    [Hashtable] RemoteCommand([ScriptBlock]$Commands, [Array]$Arguments) {
        try {
            $returnValue = 
                if($this.SessionOpen -eq $True) {
                    # Any remote invocation will involve the established session.
                    Invoke-Command -Session $this.ClientSession `
                    -ScriptBlock $Commands -ArgumentList $Arguments
                } else { Throw("The client session is not available for $($this.Hostname).") }
            return [Object]@{Success = $True; Result = $returnValue}
        } catch {
            Write-Host "~~~~ Error caught during remote command: $_" -ForegroundColor Red
            return [Object]@{Success = $False; Result = $null}
        }
    }

    # An override for the ToString function, to get the object representation as a String.
    [String] ToString() {
        return (
            "Client: {0} [{1}] - Session Open ({2}), Valid Client ({3})" `
            -f $this.Hostname, $this.IpAddress, $this.SessionOpen, $this.IsValid
        )
    }
}



# Wrapper method to return a groups of CliMonClient instances, built from an array of strings.
Function Get-ClientInstances() {
    param([Array]$FromArray)
    $clientObjects = $FromArray | ForEach-Object { [CliMonClient]::new($_) }
    return [CliMonClient[]]$clientObjects
}


# A pipeline function to return a sorted array of CliMonClient instances, where no two of them
#  share the same IP address or hostname.
Function Get-CliMonClientUnique() {
    [cmdletbinding()]
    param([CliMonClient[]][Parameter(Mandatory=$True,ValueFromPipeline=$True)]$instancesList)
    Begin {
        $local:returnArray = @()
        $local:uniqueHostnames = @()
        $local:uniqueIpAddresses = @()
    }
    Process {
        foreach($instance in $instancesList) {
            if($instance -IsNot [CliMonClient]) {
                Write-Error ("An instance in the passed parameter was not a CliMonClient object!")
                return
            } elseif(($local:uniqueHostnames -INotContains $instance.Hostname) -And
              ($local:uniqueIpAddresses -INotContains $instance.IpAddress)) {
                # If the instance's hostname and IP are NOT in the list, add them and append it.
                $local:uniqueHostnames += $instance.Hostname
                $local:uniqueIpAddresses += $instance.IpAddress
                $local:returnArray += $instance
            }
        }
    }
    End { return $local:returnArray }
}