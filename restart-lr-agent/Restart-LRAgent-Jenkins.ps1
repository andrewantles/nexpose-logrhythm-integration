
# Specify a $Domain parameter since the Jenkins job requires one.
param(
    $Server
)

$securePassword = new-Object System.Security.SecureString
$password.ToCharArray() | % { $securePassword.AppendChar($_) }
$credential = New-Object -typename System.Management.Automation.PSCredential -argumentlist "$username",$securePassword

Write-Host "Working on $Server"

# This arguments array is required for passing into the PowerShell job object. 
$Arguments = @($Server)


# Create a job object for status and timeout tracking. 
$MyJob = Start-Job -Name StartLRAgent -Credential $Credential -ArgumentList $Arguments -ScriptBlock {

    Invoke-Command -ComputerName $args[0] -ErrorAction Stop -ScriptBlock {
        Get-Service -Name scsm | Set-Service -Status Running
    } 
}

# Wait for the job for 40 seconds, and stop it if it's still running. 
Wait-Job -Timeout 40 -Name StartLRAgent
Stop-Job -Name StartLRAgent

# Error handling and analyst feedback:
$MyJob.JobStateInfo.State
if ($MyJob.JobStateInfo.State -eq "Stopped") {

    # If hung, will most likely be the domain parameter - provide the link to check the parameter. 
    $WinLastBuildAPI = 'https://jenkins.domain.com/job/LogRhythm%20Agent%20Restart/lastBuild/api/json/'
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $WinLastBuildAPI_Object = Invoke-RestMethod -Uri $WinLastBuildAPI -Method Get
    Write-Host "Job timed out. Check Domain parameter in Jenkins job: `n" ($WinLastBuildAPI_Object.url + 'parameters/')

} elseif ($MyJob.JobStateInfo.State -eq "Completed") {

    Write-Host ($Server + " - Agent restart successful.")

} elseif ($MyJob.JobStateInfo.State -eq "Failed") {

    # If-fork to decide if it was bad creds or bad hostname. (Same output for both.)
    if ($MyJob.ChildJobs[0].JobStateInfo.Reason.Message -match 'user name or password is incorrect' ) {
        Write-Host ("- bad username/password, or unknown host.")
    } elseif ($MyJob.ChildJobs[0].JobStateInfo.Reason.Message -match 'Cannot find the computer' ) {
        Write-Host ("- bad username/password, or unknown host.")
    }

} else {
    Write-Host ('Could not find the state of the Jenkins job for server: ' + $Server)
}

#Remove the job so that it's not cluttered and piling up. 
Remove-Job -Name StartLRAgent
