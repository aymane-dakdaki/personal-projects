[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter(Mandatory=$true, HelpMessage="Specify the main task: UserManagement, SystemUpdates, EventMonitoring, BackupData, RestoreData")]
    [ValidateSet("UserManagement", "SystemUpdates", "EventMonitoring", "BackupData", "RestoreData")]
    [string]$Task,

    # UserManagement Parameters
    [Parameter(ParameterSetName="UserManagementTask")]
    [ValidateSet("CreateUser", "SetPassword", "AddToGroup", "RemoveFromGroup", "DisableUser", "EnableUser", "RemoveUser", "GetUserInfo")]
    [string]$UserAction,
    [Parameter(ParameterSetName="UserManagementTask")]
    [string]$UserName,
    [Parameter(ParameterSetName="UserManagementTask")]
    [System.Security.SecureString]$Password,
    [Parameter(ParameterSetName="UserManagementTask")]
    [string]$FullName,
    [Parameter(ParameterSetName="UserManagementTask")]
    [string]$UserDescription = "User Account",
    [Parameter(ParameterSetName="UserManagementTask")]
    [string]$GroupName,

    # SystemUpdates Parameters
    [Parameter(ParameterSetName="SystemUpdatesTask")]
    [ValidateSet("CheckUpdates", "InstallUpdates")]
    [string]$UpdateAction,

    # EventMonitoring Parameters
    [Parameter(ParameterSetName="EventMonitoringTask")]
    [string]$LogName = "System",
    [Parameter(ParameterSetName="EventMonitoringTask")]
    [int[]]$EventID,
    [Parameter(ParameterSetName="EventMonitoringTask")]
    [int[]]$EventLevel,
    [Parameter(ParameterSetName="EventMonitoringTask")]
    [string]$EventSource,
    [Parameter(ParameterSetName="EventMonitoringTask")]
    [string]$AlertLogPath = "C:\Temp\EventAlerts.log",
    [Parameter(ParameterSetName="EventMonitoringTask")]
    [int]$MaxLogEvents = 20,
    [Parameter(ParameterSetName="EventMonitoringTask")]
    [switch]$ContinuousMonitoring,
    [Parameter(ParameterSetName="EventMonitoringTask")]
    [int]$IntervalSeconds = 60,

    # BackupData Parameters
    [Parameter(ParameterSetName="BackupDataTask")]
    [string[]]$SourcePaths,
    [Parameter(ParameterSetName="BackupDataTask")]
    [string]$BackupDestinationPath,
    [Parameter(ParameterSetName="BackupDataTask")]
    [string]$BackupNamePrefix = "Backup",

    # RestoreData Parameters
    [Parameter(ParameterSetName="RestoreDataTask")]
    [ValidateSet("ListBackups", "RestoreBackup")]
    [string]$RestoreAction,
    [Parameter(ParameterSetName="RestoreDataTask")]
    [string]$BackupFolderPath,
    [Parameter(ParameterSetName="RestoreDataTask")]
    [string]$BackupFileFullName, # Optional for RestoreBackup, will prompt
    [Parameter(ParameterSetName="RestoreDataTask")]
    [string]$RestoreDestinationPath # Mandatory for RestoreBackup if Action is RestoreBackup
)

#Requires -RunAsAdministrator

# --- Helper Functions ---
function Test-LocalUserExistsHelper {
    param ([string]$UserParam)
    try { Get-LocalUser -Name $UserParam -ErrorAction Stop | Out-Null; return $true } catch { return $false }
}

function Test-LocalGroupExistsHelper {
    param ([string]$GroupParam)
    try { Get-LocalGroup -Name $GroupParam -ErrorAction Stop | Out-Null; return $true } catch { return $false }
}

function Write-EventAlertHelper {
    param ([Microsoft.Diagnostics.Tracing.EventRecord]$EventParam, [string]$AlertLogPathParam)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $AlertMessage = "[$Timestamp] ALERT! Log: $($EventParam.LogName), Level: $($EventParam.LevelDisplayName), Provider: $($EventParam.ProviderName), ID: $($EventParam.Id), Message: $($EventParam.Message -replace "`r`n|`n"," ")"
    Write-Host $AlertMessage -ForegroundColor Yellow
    try { Add-Content -Path $AlertLogPathParam -Value $AlertMessage -ErrorAction Stop } catch { Write-Warning "Failed to write to alert log '$AlertLogPathParam'. Error: $($_.Exception.Message)" }
}

function Get-BackupFilesHelper {
    param ([string]$FolderParam)
    Get-ChildItem -Path $FolderParam -Filter "*.zip" | Select-Object -ExpandProperty Name
}


# --- Main Task Switch ---
# Lkhdma lra2issia katbdahna 3la 7sab l Task li khtaritih
switch ($Task) {
    "UserManagement" {
        Write-Host "--- User Account Management ---" -ForegroundColor Green
        if (-not $UserAction) { Write-Error "For -Task UserManagement, -UserAction parameter is required."; break }
        if (-not $UserName) { Write-Error "For -Task UserManagement, -UserName parameter is required."; break }

        switch ($UserAction) {
            "CreateUser" {
                if (-not (Test-LocalUserExistsHelper -UserParam $UserName)) {
                    if ($PSCmdlet.ShouldProcess($UserName, "Create Local User")) {
                        try {
                            if ($null -eq $Password) { $Password = Read-Host -Prompt "Enter password for user '$UserName'" -AsSecureString }
                            New-LocalUser -Name $UserName -Password $Password -FullName $FullName -Description $UserDescription -ErrorAction Stop
                            Write-Host "User '$UserName' created successfully."
                        } catch { Write-Error "Failed to create user '$UserName'. Error: $($_.Exception.Message)" }
                    }
                } else { Write-Warning "User '$UserName' already exists." }
            }
            "SetPassword" {
                if (Test-LocalUserExistsHelper -UserParam $UserName) {
                    if ($PSCmdlet.ShouldProcess($UserName, "Set Password for Local User")) {
                        try {
                            if ($null -eq $Password) { $Password = Read-Host -Prompt "Enter new password for user '$UserName'" -AsSecureString }
                            (Get-LocalUser -Name $UserName) | Set-LocalUser -Password $Password -ErrorAction Stop
                            Write-Host "Password for user '$UserName' set successfully."
                        } catch { Write-Error "Failed to set password for '$UserName'. Error: $($_.Exception.Message)" }
                    }
                } else { Write-Warning "User '$UserName' not found." }
            }
            "AddToGroup" {
                if (-not $GroupName) { Write-Error "GroupName parameter is required for AddToGroup action."; break }
                if (Test-LocalUserExistsHelper -UserParam $UserName) {
                    if (Test-LocalGroupExistsHelper -GroupParam $GroupName) {
                        if ($PSCmdlet.ShouldProcess("$UserName to group $GroupName", "Add Local User to Group")) {
                            try { Add-LocalGroupMember -Group $GroupName -Member $UserName -ErrorAction Stop; Write-Host "User '$UserName' added to group '$GroupName'." } catch { Write-Error "Failed to add '$UserName' to '$GroupName'. Error: $($_.Exception.Message)" }
                        }
                    } else { Write-Warning "Group '$GroupName' not found." }
                } else { Write-Warning "User '$UserName' not found." }
            }
            "RemoveFromGroup" {
                if (-not $GroupName) { Write-Error "GroupName parameter is required for RemoveFromGroup action."; break }
                if (Test-LocalUserExistsHelper -UserParam $UserName) {
                    if (Test-LocalGroupExistsHelper -GroupParam $GroupName) {
                        if ($PSCmdlet.ShouldProcess("$UserName from group $GroupName", "Remove Local User from Group")) {
                            try { Remove-LocalGroupMember -Group $GroupName -Member $UserName -ErrorAction Stop; Write-Host "User '$UserName' removed from group '$GroupName'." } catch { Write-Error "Failed to remove '$UserName' from '$GroupName'. Error: $($_.Exception.Message)" }
                        }
                    } else { Write-Warning "Group '$GroupName' not found." }
                } else { Write-Warning "User '$UserName' not found." }
            }
            "DisableUser" {
                if (Test-LocalUserExistsHelper -UserParam $UserName) {
                    if ($PSCmdlet.ShouldProcess($UserName, "Disable Local User")) {
                        try { Disable-LocalUser -Name $UserName -ErrorAction Stop; Write-Host "User '$UserName' disabled." } catch { Write-Error "Failed to disable '$UserName'. Error: $($_.Exception.Message)" }
                    }
                } else { Write-Warning "User '$UserName' not found." }
            }
            "EnableUser" {
                if (Test-LocalUserExistsHelper -UserParam $UserName) {
                    if ($PSCmdlet.ShouldProcess($UserName, "Enable Local User")) {
                        try { Enable-LocalUser -Name $UserName -ErrorAction Stop; Write-Host "User '$UserName' enabled." } catch { Write-Error "Failed to enable '$UserName'. Error: $($_.Exception.Message)" }
                    }
                } else { Write-Warning "User '$UserName' not found." }
            }
            "RemoveUser" {
                if (Test-LocalUserExistsHelper -UserParam $UserName) {
                    if ($PSCmdlet.ShouldProcess($UserName, "Remove Local User")) {
                        try { Remove-LocalUser -Name $UserName -Confirm:$false -ErrorAction Stop; Write-Host "User '$UserName' removed." } catch { Write-Error "Failed to remove '$UserName'. Error: $($_.Exception.Message)" }
                    }
                } else { Write-Warning "User '$UserName' not found." }
            }
            "GetUserInfo" {
                 if (Test-LocalUserExistsHelper -UserParam $UserName) {
                    try { Get-LocalUser -Name $UserName -ErrorAction Stop } catch { Write-Error "Failed to get info for '$UserName'. Error: $($_.Exception.Message)" }
                } else { Write-Warning "User '$UserName' not found." }
            }
            default { Write-Error "Invalid -UserAction specified for UserManagement task." }
        }
    } # End UserManagement

    "SystemUpdates" {
        Write-Host "--- System Updates & Patch Management ---" -ForegroundColor Green
        if (-not $UpdateAction) { Write-Error "For -Task SystemUpdates, -UpdateAction parameter is required."; break }

        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Error "PSWindowsUpdate module is not installed. Please install it first."
            Write-Host "To install: Run PowerShell as Administrator and execute:"
            Write-Host "Install-Module PSWindowsUpdate -Force -SkipPublisherCheck; Import-Module PSWindowsUpdate"
            exit 1
        }
        try { Import-Module PSWindowsUpdate -ErrorAction Stop } catch { Write-Error "Failed to import PSWindowsUpdate. Error: $($_.Exception.Message)"; exit 1 }

        switch ($UpdateAction) {
            "CheckUpdates" {
                Write-Host "Checking for available Windows Updates..."
                if ($PSCmdlet.ShouldProcess("System", "Check for Windows Updates")) {
                    try {
                        $updates = Get-WindowsUpdate -ErrorAction Stop
                        if ($updates) { Write-Host "Available updates:"; $updates | Format-Table -AutoSize Title, KB, Size } else { Write-Host "No updates found or system is up to date." }
                    } catch { Write-Error "Failed to check for updates. Error: $($_.Exception.Message)" }
                }
            }
            "InstallUpdates" {
                Write-Host "Attempting to download and install all available Windows Updates..."
                Write-Warning "This action might require a system reboot."
                if ($PSCmdlet.ShouldProcess("System", "Install Windows Updates")) {
                    try {
                        Install-WindowsUpdate -AcceptAll -Install -Verbose -ErrorAction Stop 
                        Write-Host "Windows Update installation process initiated. Check system logs for details and reboot status."
                    } catch { Write-Error "Failed to install updates. Error: $($_.Exception.Message)" }
                }
            }
            default { Write-Error "Invalid -UpdateAction specified for SystemUpdates task." }
        }
    } # End SystemUpdates

    "EventMonitoring" {
        Write-Host "--- System Event Monitoring & Alerting ---" -ForegroundColor Green
        $AlertLogDir = Split-Path -Path $AlertLogPath -Parent
        if (-not (Test-Path -Path $AlertLogDir)) {
            try { New-Item -ItemType Directory -Path $AlertLogDir -Force -ErrorAction Stop | Out-Null; Write-Host "Created alert log directory: $AlertLogDir" } catch { Write-Error "Failed to create alert log directory '$AlertLogDir'. Error: $($_.Exception.Message)"; exit 1 }
        }

        $FilterHt = @{ LogName = $LogName }
        if ($EventID) { $FilterHt.Add("ID", $EventID) }
        if ($EventLevel) { $FilterHt.Add("Level", $EventLevel) }
        if ($EventSource) { $FilterHt.Add("ProviderName", $EventSource) }

        $LastEventTime = (Get-Date).AddMinutes(-5) # Initialize to check last 5 mins for first run
        
        Write-Host "Monitoring Event Log: $LogName"
        Write-Host "Filter: $($FilterHt | Out-String)"
        Write-Host "Alerts will be logged to: $AlertLogPath"
        if ($ContinuousMonitoring) { Write-Host "Running continuously. Interval: $IntervalSeconds s. Press Ctrl+C to stop." }

        do {
            try {
                $CurrentFilterForIteration = $FilterHt.Clone()
                $CurrentFilterForIteration.Add("StartTime", $LastEventTime)
                
                $EventsFound = Get-WinEvent -FilterHashtable $CurrentFilterForIteration -MaxEvents $MaxLogEvents -ErrorAction SilentlyContinue
                
                if ($EventsFound) {
                    $NewestTimeThisBatch = $LastEventTime
                    foreach ($Evt in ($EventsFound | Sort-Object TimeCreated)) {
                        if ($Evt.TimeCreated -gt $LastEventTime) { # Process only newer events
                            Write-EventAlertHelper -EventParam $Evt -AlertLogPathParam $AlertLogPath
                            if ($Evt.TimeCreated -gt $NewestTimeThisBatch) {
                                $NewestTimeThisBatch = $Evt.TimeCreated
                            }
                        }
                    }
                    if ($NewestTimeThisBatch -gt $LastEventTime) {
                        $LastEventTime = $NewestTimeThisBatch 
                    }
                } elseif (-not $ContinuousMonitoring) {
                    Write-Host "No matching events found since $($LastEventTime)."
                }
            } catch { Write-Warning "Error during event log check: $($_.Exception.Message)" }
            if ($ContinuousMonitoring) { Start-Sleep -Seconds $IntervalSeconds }
        } while ($ContinuousMonitoring)
        Write-Host "Event monitoring stopped."
    } # End EventMonitoring

    "BackupData" {
        Write-Host "--- Backup Critical Data ---" -ForegroundColor Green
        if (-not $SourcePaths) { Write-Error "For -Task BackupData, -SourcePaths parameter is required."; break }
        if (-not $BackupDestinationPath) { Write-Error "For -Task BackupData, -BackupDestinationPath parameter is required."; break }

        foreach ($SPath in $SourcePaths) { if (-not (Test-Path -Path $SPath)) { Write-Error "Source path '$SPath' not found. Aborting."; exit 1 } }
        if (-not (Test-Path -Path $BackupDestinationPath)) {
            Write-Host "Destination path '$BackupDestinationPath' not found. Creating it."
            try { New-Item -ItemType Directory -Path $BackupDestinationPath -Force -ErrorAction Stop | Out-Null } catch { Write-Error "Failed to create destination '$BackupDestinationPath'. Error: $($_.Exception.Message)."; exit 1 }
        }

        $Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $ZipFileName = "$($BackupNamePrefix)_$($Timestamp).zip"
        $FullZipPath = Join-Path -Path $BackupDestinationPath -ChildPath $ZipFileName

        Write-Host "Starting backup of $($SourcePaths -join ', ') to $FullZipPath"
        if ($PSCmdlet.ShouldProcess($FullZipPath, "Create Backup Archive")) {
            try { Compress-Archive -Path $SourcePaths -DestinationPath $FullZipPath -Force -ErrorAction Stop; Write-Host "Backup completed: $FullZipPath" } catch { Write-Error "Backup failed. Error: $($_.Exception.Message)" }
        }
    } # End BackupData

    "RestoreData" {
        Write-Host "--- Restore Critical Data ---" -ForegroundColor Green
        if (-not $RestoreAction) { Write-Error "For -Task RestoreData, -RestoreAction parameter is required."; break }
        if (-not $BackupFolderPath) { Write-Error "For -Task RestoreData, -BackupFolderPath parameter is required."; break }
        if ($RestoreAction -eq "RestoreBackup" -and (-not $RestoreDestinationPath)) { Write-Error "For -RestoreAction RestoreBackup, -RestoreDestinationPath is required."; break }

        if (-not (Test-Path -Path $BackupFolderPath -PathType Container)) { Write-Error "Backup folder '$BackupFolderPath' not found."; exit 1 }

        switch ($RestoreAction) {
            "ListBackups" {
                Write-Host "Available backups in '$BackupFolderPath':"
                $BackupFiles = Get-BackupFilesHelper -FolderParam $BackupFolderPath
                if ($BackupFiles) { $BackupFiles } else { Write-Host "No backup ZIPs found." }
            }
            "RestoreBackup" {
                if (-not (Test-Path -Path $RestoreDestinationPath -PathType Container)) {
                    Write-Host "Restore destination '$RestoreDestinationPath' not found. Creating."
                    try { New-Item -ItemType Directory -Path $RestoreDestinationPath -Force -ErrorAction Stop | Out-Null } catch { Write-Error "Failed to create restore destination. Error: $($_.Exception.Message)."; exit 1 }
                }
                if (-not $BackupFileFullName) {
                    Write-Host "Available backups in '$BackupFolderPath':"
                    $AvailBackups = Get-BackupFilesHelper -FolderParam $BackupFolderPath
                    if (-not $AvailBackups) { Write-Warning "No backups found."; exit 1 }
                    for ($j = 0; $j -lt $AvailBackups.Count; $j++) { Write-Host "$($j+1). $($AvailBackups[$j])" }
                    try { $ChoiceIn = Read-Host -Prompt "Enter backup number to restore"; $ChoiceIdx = [int]$ChoiceIn - 1; if ($ChoiceIdx -ge 0 -and $ChoiceIdx -lt $AvailBackups.Count) { $BackupFileFullName = $AvailBackups[$ChoiceIdx] } else { Write-Error "Invalid selection."; exit 1 } } catch { Write-Error "Invalid input."; exit 1 }
                }
                $FullBkpPath = Join-Path -Path $BackupFolderPath -ChildPath $BackupFileFullName
                if (-not (Test-Path -Path $FullBkpPath -PathType Leaf)) { Write-Error "Backup file '$FullBkpPath' not found."; exit 1 }
                
                $RestoreFolderName = $BackupFileFullName -replace ".zip$", ""
                $FinalRestorePth = Join-Path -Path $RestoreDestinationPath -ChildPath $RestoreFolderName
                if (-not (Test-Path -Path $FinalRestorePth)) { try { New-Item -ItemType Directory -Path $FinalRestorePth -Force -ErrorAction Stop | Out-Null } catch { Write-Error "Failed to create restore subfolder. Error: $($_.Exception.Message)"; exit 1 } }

                Write-Host "Restoring $FullBkpPath to $FinalRestorePth"
                Write-Warning "This may overwrite existing files."
                if ($PSCmdlet.ShouldProcess($FinalRestorePth, "Restore from $FullBkpPath")) {
                    try { Expand-Archive -Path $FullBkpPath -DestinationPath $FinalRestorePth -Force -ErrorAction Stop; Write-Host "Restore completed." } catch { Write-Error "Restore failed. Error: $($_.Exception.Message)" }
                }
            }
            default { Write-Error "Invalid -RestoreAction for RestoreData task." }
        }
    } # End RestoreData

    default {
        Write-Error "Invalid -Task specified. Please choose from UserManagement, SystemUpdates, EventMonitoring, BackupData, RestoreData."
    }
}
