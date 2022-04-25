<#
    .DESCRIPTION
        Compares host records from Nexpose and LogRhythm deployments 
        and produces a CSV report detailing which Nexpose hosts are in LogRhythm, are 
        logging, have agents, or not. 
#>

#=====================Pull LR tables and store in .\data=====================#

# LogRhythm Entity Host Record Identifiers table, excluding retired. 
$LRHostID = Invoke-Sqlcmd -Query "SELECT [requiredColumn1]
                ,[requiredColumn2]
                ,[requiredColumnN]
             FROM [LogRhythmDB].[dbo].[HostID]
             WHERE RetiredDate is NULL"

Export-Clixml -InputObject $LRHostID -Path ".\data\LRHostID.xml"
# Zero out the variable.
Remove-Variable LRHostID

# LogRhythm System Monitor Agents table - non-system & non-retired rows only. 
$LRSMA = Invoke-Sqlcmd -Query "SELECT [requiredColumn1]
                ,[requiredColumn2]
                ,[requiredColumnN]
          FROM [LogRhythmDB].[dbo].[agent]
          WHERE SystemMonitorID > 0 AND RecordStatus != 0"

Export-Clixml -InputObject $LRSMA -Path ".\data\LRSMA.xml"
# Zero out the variable.
Remove-Variable LRSMA


# LogRhythm Pending SMA table.
$LRPendSMA = Invoke-Sqlcmd -Query "SELECT [requiredColumn1]
                ,[requiredColumn2]
                ,[requiredColumnN]
          FROM [LogRhythmDB].[dbo].[AgentPend]"

Export-Clixml -InputObject $LRPendSMA -Path ".\data\LRPendSMA.xml"
# Zero out the variable.
Remove-Variable LRPendSMA


# LogRhythm Log Sources table.
$LRMsgSrc = Invoke-Sqlcmd -Query "SELECT [requiredColumn1]
                ,[requiredColumn2]
                ,[requiredColumnN]
              FROM [LogRhythmDB].[dbo].[LogSrc]
              WHERE MsgSourceID > 0 and RecordStatus != 0 and 
              Name not like 'WinFileMon' and
              Name not like 'WinDataDefender' and
              Name not like 'UserActivityMonitor' and
              Name not like 'ProcessMonitor' and
              Name not like 'NetworkConnectionMonitor' and
              Name not like 'RegistryMonitor' and
              Name not like 'LinuxFileMon'"

Export-Clixml -InputObject $LRMsgSrc -Path ".\data\LRMsgSrc.xml"
# Zero out the variable.
Remove-Variable LRMsgSrc

# Clear memory using PowerShell GarbageCollector.
[System.GC]::Collect()


#=====================Pull a copy of the Nexpose dataset===================#


# Encode API User cred pair to base64 Basic Authentication format.
$Auth = '<api-username>:<api-password>'
$UTF8 = [System.Text.Encoding]::UTF8.GetBytes($Auth)
$Base64Auth = [System.Convert]::ToBase64String($UTF8)

# Add encoded creds to HTTP header.
$Headers = @{
    "Authorization" = "Basic $Base64Auth"
    "Content-Type" = "application/json"
}

# Initial query to determine the size of the current Nexpose dataset. 
$PageURL = "https://nexpose.apiurl.com/api/3/assets?size=999"
$PageResponse = Invoke-RestMethod -Uri $PageURL -Headers $Headers -Method GET
$PageTotal = $PageResponse.page.totalPages
Remove-Variable PageResponse      # 'Zeroing' out this large variable to relieve memory pressure. 

$PageNo = 0 

# Iterate through every "page" of Nexpose data considering all hosts. 
while ($PageNo -lt $PageTotal) {

    $AssetURL = "https://nexpose.apiurl.com/api/3/assets?size=999&page=$PageNo"
    $AssetResponse = Invoke-RestMethod -Uri $AssetURL -Headers $Headers -Method GET
    $PageData = $AssetResponse.resources #Just need the asset data. 
    Remove-Variable AssetResponse    # Zero out this variable until it is needed again. 

#=====================Parse out only qualified hosts from the Nexpose dataset===================#

    # Setup variables to be used to for filtering the data. Filter data by moving 
    # data between variables, and stripping unwanted data between moves. 
    # Remove the variable before creating it, if it already exists. 
    if ($NXTempData) {Remove-Variable NXTempData} ; $NXTempData = @()
    if ($NXTempData2) {Remove-Variable NXTempData2} ; $NXTempData2 = @()
    if ($NXTempData3) {Remove-Variable NXTempData3} ; $NXTempData3 = @()

    # Establish '30 days ago' mark in correct time format for comparison w Nexpose.
    $30daysago = ((Get-Date).AddDays(-30)).ToUniversalTime().ToString('yyyy-MM-ddThh:mm:ss.fffZ')
    # Create a new array of assets, less asset not seen in last 30 days.  
    foreach ( $item in 0..($PageData.count-1) ) {
        
        $ItemLastDate = $PageData[$item].history[$PageData[$item].history.Count-1].date
        if ($ItemLastDate -gt $30daysago) {
            # Build a new, "refined" object to hold just the required data points from Nexpose.
            # This object is also part of the final report's output format.  
            $NXObjRefined = [PSCustomObject][ordered]@{
                NexposeID = $PageData[$item].id
                NexposeIP = $PageData[$item].ip
                Hostname = $PageData[$item].hostName
                OS = $PageData[$item].os
            }
            $NXTempData += $NXObjRefined
        }
    }

    # Check variable counts. ("Debug", terminal standard output)
    Write-Host " `$PageData count is: $($PageData.Count)"
    Write-Host " `$NXTempData count is: $($NXTempData.Count)"
    Write-Host " `$NXTempData2 count is: $($NXTempData2.Count)"
    Write-Host " `$NXTempData3 count is: $($NXTempData3.count)"

    #Zero out the $PageData variable until it's needed again. 
    Remove-Variable PageData

    #IP-matching regex:
    #Matches only internal IPs starting with "10."
    $IPMatch10 = '^(10)\.(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.){2}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'
    #Matches only internal IPs starting with "172.16" through "172.32"
    $IPMatch172 = '^(172)\.(1[6-9]|2[0-9]|3[0,1,2])\.(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.)([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'
    #Matches only internal IPs starting with "192.168."
    $IPMatch192 = '^(192\.168\.)(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.)([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])$'
    # Remove everything that's not an internal IP.
    # NXTempData2 now holds the trimmed data pulled from the Nexpose API.
    foreach ($item in $NXTempData) {
        if (
            ($item.NexposeIP -match $IPMatch10) 
            -or ($item.NexposeIP -match $IPMatch192) 
            -or ($item.NexposeIP -match $IPMatch172)
        ) { 
            $NXTempData2 += $item 
        }
    }

    # Check variable counts. ("Debug", terminal standard output)
    Write-Host " `$PageData count is: $($PageData.Count)"
    Write-Host " `$NXTempData count is: $($NXTempData.Count)"
    Write-Host " `$NXTempData2 count is: $($NXTempData2.Count)"
    Write-Host " `$NXTempData3 count is: $($NXTempData3.count)"
    
    # Zero out the temp holding variable until needed again. 
    Remove-Variable NXTempData; $NXTempData = @()

    foreach ($item in $NXTempData2) {
        # Filter to only include Nexpose assets that have server OS identification,
        # as well as hosts that do not include "dev," "stage," etc. in hostname.
        if (
            ($item.OS -match 'Windows Server') 
            -Or ($item.OS -match 'unix') 
            -Or ($item.OS -match 'linux')
        ) {
            if (
                ($item.hostName -notmatch 'stage') -And ($item.hostName -notmatch 'dev') -And 
                ($item.hostName -notmatch 'test') -And ($item.hostName -notmatch "^.*-[sSdDtT]+$")
            ) {
                $NXTempData3 += $item
            }
        }
    }

    # Check variable counts. ("Debug", terminal standard output)
    Write-Host " `$PageData count is: $($PageData.Count)"
    Write-Host " `$NXTempData count is: $($NXTempData.Count)"
    Write-Host " `$NXTempData2 count is: $($NXTempData2.Count)"
    Write-Host " `$NXTempData3 count is: $($NXTempData3.count)"

    # Append a page number and store $NXTempData3, the filtered, reformatted dataset, to disk. 
    Export-Clixml -InputObject $NXTempData3 -Path ".\data\NX-inv-pg$PageNo.xml"
    $PageNo ++

    #Clear memory using PowerShell GarbageCollector.
    [System.GC]::Collect()
}

#Final memory clear after all Nexpose data is filtered, formatted and saved to disk. 
Remove-Variable PageData
Remove-Variable NXTempData
Remove-Variable NXTempData2
Remove-Variable NXTempData3
[System.GC]::Collect()


#===================== Compare each Nexpose asset with LR ===================#

$PageNo = 0
$Results = @()

while ($PageNo -lt ($PageTotal + 1)) {

    $PageData = Import-Clixml -Path ".\data\NX-inv-pg$PageNo.xml"
    $RecordCount = 0

    foreach ($NXitem in $PageData) {
        $Num = 2 #Used for adding log source IDs to object record, later.
        $OutputObj = [PSCustomObject][ordered]@{ # OutputObj represents final report column names. 
            NexposeID = $NXitem.NexposeID
            NexposeIP = $NXitem.NexposeIP
            Hostname = $NXitem.Hostname
            OS = $NXItem.OS
            HasLRHostRecord = "No"
            LRHostID = ""
            HasLRAgent = "No"
            LRSysMonID = ""
            HasLRLogging = "No"
            LRLogSrcID = ""
            LRLogSrcID2 = ""
            LRLogSrcID3 = ""
            PageNo = $PageNo
            RecordNo = $RecordCount
        }

        # Check if NX IP or HostName are in the LR HostID database table: 
        $TempCompare = Import-Clixml -Path ".\data\LRHostID.xml"
        foreach ($LRitem in $TempCompare) {

            if ( 
                ($NXitem.ip -eq $LRitem.value) 
                -or ($NXitem.hostName -eq $LRitem.value) 
            ) {   
                $OutputObj.HasLRHostRecord = "Yes"
                $OutputObj.LRHostID = $LRitem.HostID
                $Results += (Get-Date).ToString() + "Nexpose item (Page|Record): ($PageNo|$RecordCount) $($OutputObj.nexposeip) $($OutputObj.hostname) MATCHED a Host Identifier in LogRhythm."
            }
        }

        #Next, check if there is a pending LogRhythm agent.
        Remove-Variable TempCompare; [System.GC]::Collect()
        $TempCompare = Import-Clixml -Path ".\data\LRPendSMA.xml"
        foreach ($LRitem in $TempCompare) {
            if ( 
                ($OutputObj.NexposeIP -eq $LRitem.IPAddress)
                -or $OutputObj.Hostname -eq $LRitem.Hostname) 
            {
                $OutputObj.HasLRAgent = "Pending"
                $Results += (Get-Date).ToString() + "Nexpose item (Page|Record): ($PageNo|$RecordCount) $($OutputObj.nexposeip) $($OutputObj.hostname) MATCHED a Pending Agent in LogRhythm."     
            }
        }

        #Next, check if there is a LogRhythm agent record for the host
        Remove-Variable TempCompare; [System.GC]::Collect()
        $TempCompare = Import-Clixml -Path ".\data\LRSMA.xml"
        foreach ($LRitem in $TempCompare) {

            if ($OutputObj.LRHostID -eq $LRitem.HostID) {
            
                $OutputObj.HasLRAgent = "Yes"
                $OutputObj.LRSysMonID = $LRitem.SystemMonitorID
                $Results += (Get-Date).ToString() + "Agent ID found $($LRitem.SystemMonitorID) for (Page|Record): ($PageNo|$RecordCount) $($OutputObj.nexposeip) $($OutputObj.hostname)"
            }            
        }
 
        #Next, check if there is logging.
        Remove-Variable TempCompare; [System.GC]::Collect()
        $TempCompare = Import-Clixml -Path ".\data\LRMsgSrc.xml"
        foreach ($LRitem in $TempCompare) {
        
            if ($OutputObj.LRHostID -eq $LRitem.HostID) {
                
                #Write-Output "Logging match for HostID: $($OutputObj.LRHostID) MsgID: $($LRitem.MsgSourceID)"        
                $OutputObj.HasLRLogging = "Yes"
                if ($OutputObj.LRLogSrcID -eq "") { 
                    
                    #Write-Output "No existing log ID found in final output for record."
                    $OutputObj.LRLogSrcID = $LRitem.MsgSourceID 
                    $Results += (Get-Date).ToString() + "LogSource ID found $($LRitem.MsgSourceID) for (Page|Record): ($PageNo|$RecordCount) $($OutputObj.nexposeip) $($OutputObj.hostname)"
                    Continue

                }
                if ($OutputObj.LRLogSrcID -ne "") { 
                    
                    #Write-Output "Adding column: existing log ID found in final output for record."
                    Add-Member -InputObject $OutputObj -NotePropertyName "LRLogSrcID$Num" -NotePropertyValue $LRitem.MsgSourceID -Force -Verbose
                    $Results += (Get-Date).ToString() + "LogSource ID found $Num | $($LRitem.MsgSourceID) for (Page|Record): ($PageNo|$RecordCount) $($OutputObj.nexposeip) $($OutputObj.hostname)"
                    $Num ++

                }
            
            }            

        } 
        Remove-Variable TempCompare; [System.GC]::Collect()
        
        $ReportDate = Get-Date -Format yyyy-MM-dd
        Export-Csv -InputObject $OutputObj -Path "\\UNC\path\LR2NX_validation\$ReportDate`_LR2NX-Validation-Report.csv" -Append -NoTypeInformation -Force

        Write-Output "Page - Record: $PageNo - $RecordCount"
        $RecordCount ++
    }
    $PageNo ++
}

foreach ($line in $Results) {
    $line | Out-File -FilePath .\log-out.txt -Append
}
