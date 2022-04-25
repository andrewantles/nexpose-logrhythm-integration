<#
    .Synopsis 
        Restarts the LogRhythm Agent service (scsm.exe) automatically as an alarm SmartResponse action.
        
    .Description
        When an 'Agent Heartbeat Missed' alarm is triggered, this script will send the required 
	parameters to both Jenkins servers (Linux-side & Windows-side), via API requests. 
 
    .Parameter <all>
        Parameters are configured in the LogRhythm Console and are passed to the script in response to an alarm firing. 
        NOTE: Variable alarm paramater should be: Type: Alarm Field, Value: Known Host (Impacted) 

    .Example
        powershell.exe -file <path_to>\Restart-LRAgent-SRP.ps1 <server_to_restart>
       
    .Output
        Write-Host to Standard Out, viewable in the LogRhythm Web Console after running. 
#>

# Accept servername as first and only argument.:
$Server = $args[0]
# Linux/IP only indicator:
$IP_LinuxOnly = 0
# Indicates whether to display job feedback. 
$Lin_FeedbackOK = 0
$Win_FeedbackOK = 0


function Build-WinJenkins ($TargetServer) {
    # Windows job URL:
    # I would never send a token in plaintext in a URL, but this was required for this environment, 
    and use of a service account instead has been declined. 
    $WinURL = 'https://jenkins.domain.com/job/LogRhythm%20Agent%20Restart/buildWithParameters'
    # Credential:
    $Auth = '<token>'

    #Need to know what domain to send along as a Jenkins job parameter.
    $Domain = @()
    $Domains = [ordered]@{
	    DOMAIN00 = '.domain.com';
	    DOMAIN01 = '.domain.local';
	    DOMAIN02 = '.domain2.local';
	    DOMAIN03 = '.domain3.local';
	    DOMAIN04 = '.domain4.local';
	    DOMAIN05 = '.domain5.local';
    }

    # Brute-force iterate through all domain prefixes, checking for successful DNS resolution.
    # If DNS resolves, update the domain parameter before sending to Jenkins. 
    $Domains.GetEnumerator() | ForEach-Object {
        if (Resolve-DnsName -Name ($TargetServer + $_.value) -ErrorAction SilentlyContinue) {
            $Domain += $_.key
        }
    }

    # Some of the domains require FQDN and some are okay with just the hostname.
    # Check if FQDN is required and add if needed.
    $DomainsNeedingHelp = [ordered]@{
		DOMAIN00 = '.domain.com';
		DOMAIN01 = '.domain.local';
    }
    $DomainsNeedingHelp.GetEnumerator() | ForEach-Object {
        if (($Domain[0] -eq $_.key)) {
            $TargetServer = $TargetServer + $_.value
        }
    }

    #Jenkins job parameters go here. 
    $Body = @{
		Server = $TargetServer
		Domain = $Domain[0]
	}

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        Invoke-RestMethod -Uri $WinURL -Body $Body -Method Post -ErrorAction Stop
        Write-Host ("-----------------------------------------------------------------------------------------------------------------------`n")
        Write-Host ("Agent restart request sent to Windows-Jenkins for: " + $Domain[0] +"\"+ $TargetServer)
        $Win_FeedbackOK = 1
    } 
    catch {
        Write-Host ("-----------------------------------------------------------------------------------------------------------------------`n")
        Write-Host ("Error: Failed sending agent restart request to Windows-Jenkins for: " + $Domain[0] +"\"+ $TargetServer)
    }
}


function Build-LnxJenkins ($TargetServer) {
    # Main difference between this and Windows, is that I have to run a 'status' job after the 'start' job to get the job results.  
    # Linux job URL
    $LinuxURLHTTPS = 'https://jenkins.bluestembrands.comjob/logrhythm/buildWithParameters'
    # Credential:
    $Auth = '<token>'

    # Convert $Auth to Base64 encoded Basic Authentixtaion and add to headers. 
    $UTF8 = [System.Text.Encoding]::UTF8.GetBytes($Auth)
    $Base64Auth = [System.Convert]::ToBase64String($UTF8)

    # Check if a host only resolves with a domain suffix and add if needed. 
    $Domains = [ordered]@{
		DOMAIN00 = '.domain.com';
		DOMAIN01 = '.domain.local';
		DOMAIN02 = '.domain2.local';
		DOMAIN03 = '.domain3.local';
		DOMAIN04 = '.domain4.local';
		DOMAIN05 = '.domain5.local';
    }
    $Domains.GetEnumerator() | ForEach-Object {
        if (Resolve-DnsName -Name ($TargetServer + $_.value) -ErrorAction SilentlyContinue) {
            $TargetServer = ($TargetServer + $_.value)
        }
    }

    # Job authentication is sent via the header. 
    $Headers = @{ 
    	"Authorization" = "Basic $Base64Auth" 
    }

    #Jenkins job parameters go here. 
    $Body = @{
		HOST_NAME = $TargetServer
		STATE = 'start'
    }

    # Send the job to Jenkins, writing a message if sending failed. 
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    try {
        Invoke-RestMethod -Uri $LinuxURLHTTPS -Headers $Headers -Body $Body -Method Post
        Write-Host ("-----------------------------------------------------------------------------------------------------------------------`n")
        Write-Host ("Agent restart request sent to Linux-Jenkins for: " + $TargetServer)
        $Lin_FeedbackOK = 1
    } 
    catch {
        Write-Host ("-----------------------------------------------------------------------------------------------------------------------`n")
        Write-Host ("Error: Failed sending agent restart request to Linux-Jenkins for: " + $TargetServer)
    }

    # Wait 30 seconds for the job to run, then run a 'status' job to check outcome.
    Start-Sleep -Seconds 30
    $Body = @{
   		HOST_NAME = $TargetServer
		STATE = 'status'
    }

    # Not going to check if status job failed to send. Assume success if the other was successful. 
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-RestMethod -Uri $LinuxURLHTTPS -Headers $Headers -Body $Body -Method Post
}



Write-Verbose ("`nChecking agent name for: " + $Server)

# Check the server/agent names for incompatibilities, and correct them before passing to Jenkins.
if ($Server -match '(?<name>.*)\s+\(\d+\)$') {
    $Server = $matches.name

} elseif ($Server -match '^ip-(?<oct1>\d{1,3})-(?<oct2>\d{1,3})-(?<oct3>\d{1,3})-(?<oct4>\d{1,3})') {
    $Server = $matches.oct1 + '.' +$matches.oct2 + '.' + $matches.oct3 + '.' +$matches.oct4
    $IP_LinuxOnly += 1
    Write-Host ("-----------------------------------------------------------------------------------------------------------------------`n")
    Write-Host ("`nAgent name is an IP - will only send to Linux-Jenkins for: " + $Server)

} elseif ($Server -match '(?<name>.*)') {
    $Server = $matches.name
} elseif ($Server -match '(?<name>.*).domain.com') {
    $Server = $matches.name
}


# If the servername is just an IP, then don't bother sending to Windows-Jenkins. 
Write-Verbose ("`nRestart request queued for: " + $Server)
if ($IP_LinuxOnly -eq 0) { Build-WinJenkins ($Server) }
Build-LnxJenkins ($Server) 
# Pause to let the jobs build and run - so that a complete 'lastBuild' URL is generated. 
Start-Sleep -Seconds 30


# Display note that job runs on both side:
Write-Host ("===============================================================`n")
Write-Host ("* Each restart request runs for Windows and Linux -`nplease check the output applicable to this agent. *")
Write-Host ("===============================================================`n")

# Check to see that the job sent successfully, before displaying job feedback. 
# Otherwise feedback will be irrelevant to this run.
if ($Lin_FeedbackOK = 1) {
    # Display the result for the Linux job:
    $LinuxLastBuildAPI = 'https://jenkins.domain.com/job/logrhythm/lastBuild/api/json'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $LinuxLastBuildAPI_Object = Invoke-RestMethod -Uri $LinuxLastBuildAPI -Method Get
    $LinuxLastBuildAPI_Output = Invoke-RestMethod -uri ($LinuxLastBuildAPI_Object.url + 'consoleText')
    Write-Host ("`nLinux side results:")
    if (($LinuxLastBuildAPI_Output | Out-String) -match "scsmd \(pid \d*\) is running" ) {
        Write-Host "`nLinux agent restart successful."
        Write-Host ("-----------------------------------------------------------------------------------------------------------------------`n")
    } elseif (($LinuxLastBuildAPI_Output | Out-String)  -match "scsmd is stopped") {
        Write-Host ("`nLinux agent for " + $Server + " is in stopped state.")
        Write-Host ("-----------------------------------------------------------------------------------------------------------------------`n")
    } elseif (($LinuxLastBuildAPI_Output | Out-String) -match "\sout:\s+Active:\s+inactive\s+\(dead\)") {
        Write-Host ("`nLinux agent for " + $Server + " is offline.")
        Write-Host ("-----------------------------------------------------------------------------------------------------------------------`n")
    } elseif (($LinuxLastBuildAPI_Output | Out-String) -match "\sout:\s+Active:\s+.*active\s+\(running\)") {
        Write-Host ("`nLinux agent for " + $Server + " is online.")
        Write-Host ("-----------------------------------------------------------------------------------------------------------------------`n")
    } else {
        Write-Host ("`nCheck Windows results | or view Linux-side results in Jenkins:`n" + ($LinuxLastBuildAPI_Object.url + 'consoleText'))
        Write-Host ("-----------------------------------------------------------------------------------------------------------------------`n")
    }
} else {
    Write-Host ("Error: Problem sending request to Linux-Jenkins.`n")
    Write-Host ("You can review the job history at the following URL:`n")
    Write-Host ("https://jenkins.domain.com/job/logrhythm/`n")
    Write-Host ("-----------------------------------------------------------------------------------------------------------------------`n")
}

# Check to see that the job sent successfully, before displaying job feedback. 
# Otherwise feedback will be irrelevant to this run.
if ($Win_FeedbackOK = 1) {
    # Display the result for the Windows jobs:
    $WinLastBuildAPI = 'https://jenkins.domain.com/job/LogRhythm%20Agent%20Restart/lastBuild/api/json/'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $WinLastBuildAPI_Object = Invoke-RestMethod -Uri $WinLastBuildAPI -Method Get
    $WinLastBuildAPI_Output = (Invoke-RestMethod -uri ($WinLastBuildAPI_Object.url + 'consoleText'))
    Write-Host "`nWindows side results:"
    # Output displays based on what the script finds in the last job console text output.
    if (($WinLastBuildAPI_Output | Out-String) -match "- Agent restart successful.") {
        Write-Host "`nWindows agent restart successful."
        Write-Host ("-----------------------------------------------------------------------------------------------------------------------`n")
    } elseif (($WinLastBuildAPI_Output | Out-String)  -match "- bad username/password, or unknown host.") {
        Write-Host "`nCheck Linux results | or issue with Win-Jenkins creds, or Wenkins host lookup."
        Write-Host ("-----------------------------------------------------------------------------------------------------------------------`n")
    } else {
        $MyMatch = (($WinLastBuildAPI_Output | Out-String) -match "[\s\S]*(?<output>Working on[\s\S]*)Set build name.")
        Write-Host "`nCheck Linux results | or Agent restart failed - see Wenkins job page:  https://jenkins.domain.com/job/LogRhythm%20Agent%20Restart/ `n"
        Write-Host ("-----------------------------------------------------------------------------------------------------------------------`n")
    }
} else {
    Write-Host ("Error: Problem sending request to Windows-Jenkins.`n")
    Write-Host ("You can review the job history at the following URL:`n")
    Write-Host ("https://jenkins.domain.com/job/LogRhythm%20Agent%20Restart/`n")
    Write-Host ("-----------------------------------------------------------------------------------------------------------------------`n")
}
