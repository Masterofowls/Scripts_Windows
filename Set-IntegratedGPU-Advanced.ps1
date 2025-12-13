<#
.SYNOPSIS
    Advanced GPU Preference Configuration Script for Windows 11
.DESCRIPTION
    Scans all installed applications and system components to configure them to use integrated graphics.
    Supports multiple package managers and uses advanced search tools for comprehensive discovery.
.NOTES
    Author: AI Assistant
    Date: December 13, 2025
    Requires: Windows 11, Admin Rights
#>

#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$WhatIf,
    
    [Parameter()]
    [string]$LogPath = "$env:USERPROFILE\Documents\GPU_Config_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt",
    
    [Parameter()]
    [switch]$SkipEverything,
    
    [Parameter()]
    [switch]$Force
)

# ============================================================================
# SCRIPT INITIALIZATION
# ============================================================================

$ErrorActionPreference = 'Continue'
$script:ProcessedApps = @()
$script:SuccessCount = 0
$script:FailureCount = 0
$script:SkippedCount = 0

# Update LogPath to use current directory if using default
if ($LogPath -eq "$env:USERPROFILE\Documents\GPU_Config_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt") {
    $LogPath = Join-Path -Path $PSScriptRoot -ChildPath "GPU_Config_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
}

# ============================================================================
# LOGGING FUNCTIONS
# ============================================================================

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter()]
        [AllowEmptyString()]
        [string]$Message = '',
        
        [Parameter()]
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO',
        
        [Parameter()]
        [switch]$NoConsole
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = if ($Message) { "[$timestamp] [$Level] $Message" } else { "" }
    
    # Write to log file
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
    
    # Write to console with color coding
    if (-not $NoConsole) {
        switch ($Level) {
            'SUCCESS' { Write-Host $logEntry -ForegroundColor Green }
            'WARNING' { Write-Host $logEntry -ForegroundColor Yellow }
            'ERROR'   { Write-Host $logEntry -ForegroundColor Red }
            'DEBUG'   { Write-Host $logEntry -ForegroundColor Cyan }
            default   { Write-Host $logEntry -ForegroundColor White }
        }
    }
}

function Write-Section {
    param([string]$Title)
    $separator = "=" * 80
    Write-Log -Message "`n$separator" -Level INFO
    Write-Log -Message $Title -Level INFO
    Write-Log -Message "$separator" -Level INFO
}

# ============================================================================
# ADMIN RIGHTS CHECK
# ============================================================================

function Test-AdminRights {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-WithGsudo {
    if (-not (Test-AdminRights)) {
        Write-Log -Message "Script requires administrator rights. Attempting to elevate with gsudo..." -Level WARNING
        
        # Check if gsudo is available
        $gsudoPath = Get-Command gsudo -ErrorAction SilentlyContinue
        
        if ($gsudoPath) {
            Write-Log -Message "Elevating with gsudo..." -Level INFO
            $scriptPath = $MyInvocation.PSCommandPath
            
            # Build argument list for gsudo
            $argList = @(
                '-ExecutionPolicy', 'Bypass',
                '-File', "`"$scriptPath`""
            )
            
            # Add original parameters
            foreach ($key in $PSBoundParameters.Keys) {
                if ($key -eq 'WhatIf') {
                    $argList += '-WhatIf'
                } elseif ($key -eq 'SkipEverything') {
                    $argList += '-SkipEverything'
                } elseif ($key -eq 'Force') {
                    $argList += '-Force'
                } elseif ($key -eq 'LogPath') {
                    $argList += '-LogPath', "`"$($PSBoundParameters[$key])`""
                }
            }
            
            # Use gsudo with pwsh
            gsudo pwsh $argList
            exit
        } else {
            Write-Log -Message "gsudo not found. Install with: winget install gerardog.gsudo" -Level ERROR
            Write-Log -Message "Alternatively, run PowerShell 7+ as Administrator manually." -Level WARNING
            
            # Fallback to standard elevation with pwsh
            $pwshPath = (Get-Command pwsh -ErrorAction SilentlyContinue).Source
            if (-not $pwshPath) {
                $pwshPath = "pwsh"
            }
            
            $arguments = "-ExecutionPolicy Bypass -File `"$($MyInvocation.PSCommandPath)`""
            Start-Process $pwshPath -Verb RunAs -ArgumentList $arguments
            exit
        }
    }
}

# ============================================================================
# GPU PREFERENCE FUNCTIONS
# ============================================================================

function Set-GPUPreference {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AppPath,
        
        [Parameter()]
        [string]$AppName,
        
        [Parameter()]
        [ValidateSet('Integrated', 'HighPerformance', 'Default')]
        [string]$Preference = 'Integrated'
    )
    
    try {
        # Validate path exists
        if (-not (Test-Path $AppPath)) {
            Write-Log -Message "Path not found: $AppPath" -Level WARNING
            $script:SkippedCount++
            return $false
        }
        
        # Check if already processed
        if ($script:ProcessedApps -contains $AppPath) {
            Write-Log -Message "Already processed: $AppName" -Level DEBUG
            return $true
        }
        
        # Get file info
        $fileInfo = Get-Item $AppPath -ErrorAction Stop
        
        # Only process executable files
        if ($fileInfo.Extension -notin @('.exe', '.msi')) {
            Write-Log -Message "Skipping non-executable: $AppName ($($fileInfo.Extension))" -Level DEBUG
            $script:SkippedCount++
            return $false
        }
        
        $displayName = if ($AppName) { $AppName } else { $fileInfo.Name }
        
        # Map preference to Windows Graphics Setting
        $gpuPreference = switch ($Preference) {
            'Integrated'      { 1 }  # Let Windows decide (usually integrated)
            'HighPerformance' { 2 }  # High performance GPU
            default           { 0 }  # System default
        }
        
        # Registry path for Graphics Settings
        $registryPath = "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences"
        
        # Ensure registry path exists
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
            Write-Log -Message "Created registry path: $registryPath" -Level DEBUG
        }
        
        # Set GPU preference in registry
        $normalizedPath = $AppPath.Replace('/', '\')
        
        if ($WhatIf) {
            Write-Log -Message "WHATIF: Would set $displayName to use $Preference GPU" -Level INFO
            $script:SuccessCount++
        } else {
            Set-ItemProperty -Path $registryPath -Name $normalizedPath -Value "GpuPreference=$gpuPreference;" -Type String -ErrorAction Stop
            Write-Log -Message "✓ Configured: $displayName → $Preference GPU" -Level SUCCESS
            $script:SuccessCount++
        }
        
        $script:ProcessedApps += $AppPath
        return $true
        
    } catch {
        Write-Log -Message "✗ Failed to configure $displayName : $($_.Exception.Message)" -Level ERROR
        $script:FailureCount++
        return $false
    }
}

# ============================================================================
# APPLICATION DISCOVERY FUNCTIONS
# ============================================================================

function Get-WinGetApps {
    Write-Section "Scanning WinGet Applications"
    
    $apps = @()
    
    try {
        # Check if winget is available
        $winget = Get-Command winget -ErrorAction Stop
        Write-Log -Message "WinGet found. Scanning installed packages..." -Level INFO
        
        # Get installed winget packages
        $wingetList = winget list --accept-source-agreements 2>&1 | Out-String
        
        # Parse winget output and find installation paths
        $lines = $wingetList -split "`n" | Select-Object -Skip 2
        
        foreach ($line in $lines) {
            if ($line -match '^\s*(.+?)\s{2,}(.+?)\s{2,}') {
                $appName = $matches[1].Trim()
                if ($appName) {
                    Write-Log -Message "Found WinGet app: $appName" -Level DEBUG
                }
            }
        }
        
        # Scan common WinGet installation directories
        $wingetPaths = @(
            "$env:LOCALAPPDATA\Microsoft\WinGet\Packages",
            "$env:ProgramFiles\WindowsApps",
            "$env:LOCALAPPDATA\Programs"
        )
        
        foreach ($path in $wingetPaths) {
            if (Test-Path $path) {
                $exes = Get-ChildItem -Path $path -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
                foreach ($exe in $exes) {
                    $apps += [PSCustomObject]@{
                        Name = $exe.BaseName
                        Path = $exe.FullName
                        Source = 'WinGet'
                    }
                }
            }
        }
        
        Write-Log -Message "Found $($apps.Count) executables in WinGet directories" -Level INFO
        
    } catch {
        Write-Log -Message "WinGet not available or error occurred: $($_.Exception.Message)" -Level WARNING
    }
    
    return $apps
}

function Get-MicrosoftStoreApps {
    Write-Section "Scanning Microsoft Store Applications"
    
    $apps = @()
    
    try {
        # Get all AppX packages
        $appxPackages = Get-AppxPackage -AllUsers -ErrorAction Stop
        
        Write-Log -Message "Found $($appxPackages.Count) Microsoft Store packages" -Level INFO
        
        foreach ($package in $appxPackages) {
            $installLocation = $package.InstallLocation
            
            if ($installLocation -and (Test-Path $installLocation)) {
                # Find executables in package
                $exes = Get-ChildItem -Path $installLocation -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
                
                foreach ($exe in $exes) {
                    $apps += [PSCustomObject]@{
                        Name = $package.Name
                        Path = $exe.FullName
                        Source = 'MSStore'
                        PackageName = $package.PackageFullName
                    }
                }
            }
        }
        
        Write-Log -Message "Found $($apps.Count) executables in Microsoft Store apps" -Level INFO
        
    } catch {
        Write-Log -Message "Error scanning Microsoft Store apps: $($_.Exception.Message)" -Level ERROR
    }
    
    return $apps
}

function Get-ScoopApps {
    Write-Section "Scanning Scoop Applications"
    
    $apps = @()
    
    try {
        $scoopPath = "$env:USERPROFILE\scoop"
        
        if (Test-Path $scoopPath) {
            Write-Log -Message "Scoop installation found at: $scoopPath" -Level INFO
            
            $appsPath = Join-Path $scoopPath "apps"
            
            if (Test-Path $appsPath) {
                $exes = Get-ChildItem -Path $appsPath -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
                
                foreach ($exe in $exes) {
                    $apps += [PSCustomObject]@{
                        Name = $exe.BaseName
                        Path = $exe.FullName
                        Source = 'Scoop'
                    }
                }
                
                Write-Log -Message "Found $($apps.Count) executables in Scoop apps" -Level INFO
            }
        } else {
            Write-Log -Message "Scoop not installed (checked: $scoopPath)" -Level WARNING
        }
        
    } catch {
        Write-Log -Message "Error scanning Scoop apps: $($_.Exception.Message)" -Level ERROR
    }
    
    return $apps
}

function Get-ChocolateyApps {
    Write-Section "Scanning Chocolatey Applications"
    
    $apps = @()
    
    try {
        $chocoPath = "$env:ProgramData\chocolatey"
        
        if (Test-Path $chocoPath) {
            Write-Log -Message "Chocolatey installation found at: $chocoPath" -Level INFO
            
            $binPath = Join-Path $chocoPath "bin"
            $libPath = Join-Path $chocoPath "lib"
            
            foreach ($path in @($binPath, $libPath)) {
                if (Test-Path $path) {
                    $exes = Get-ChildItem -Path $path -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue
                    
                    foreach ($exe in $exes) {
                        $apps += [PSCustomObject]@{
                            Name = $exe.BaseName
                            Path = $exe.FullName
                            Source = 'Chocolatey'
                        }
                    }
                }
            }
            
            Write-Log -Message "Found $($apps.Count) executables in Chocolatey apps" -Level INFO
        } else {
            Write-Log -Message "Chocolatey not installed (checked: $chocoPath)" -Level WARNING
        }
        
    } catch {
        Write-Log -Message "Error scanning Chocolatey apps: $($_.Exception.Message)" -Level ERROR
    }
    
    return $apps
}

function Get-SystemApps {
    Write-Section "Scanning System Applications and Components"
    
    $apps = @()
    
    # Common system paths
    $systemPaths = @(
        "$env:SystemRoot\System32",
        "$env:SystemRoot\SysWOW64",
        "$env:ProgramFiles",
        "${env:ProgramFiles(x86)}",
        "$env:LOCALAPPDATA\Programs",
        "$env:LOCALAPPDATA\Microsoft\WindowsApps"
    )
    
    # Critical system applications and components
    $criticalApps = @(
        'explorer.exe',           # File Explorer
        'msedge.exe',            # Edge Browser
        'chrome.exe',            # Chrome
        'firefox.exe',           # Firefox
        'brave.exe',             # Brave
        'Taskmgr.exe',           # Task Manager
        'WindowsTerminal.exe',   # Windows Terminal
        'cmd.exe',               # Command Prompt
        'powershell.exe',        # PowerShell
        'pwsh.exe',              # PowerShell 7+
        'conhost.exe',           # Console Host
        'msedgewebview2.exe',    # Edge WebView2
        'Code.exe',              # VS Code
        'notepad.exe',           # Notepad
        'WidgetService.exe',     # Widgets
        'SearchHost.exe',        # Windows Search
        'StartMenuExperienceHost.exe',  # Start Menu
        'ShellExperienceHost.exe',      # Shell Experience
        'RuntimeBroker.exe',     # Runtime Broker
        'ApplicationFrameHost.exe',     # UWP App Frame
        'SystemSettings.exe',    # Settings App
        'SkypeApp.exe',          # Skype
        'Teams.exe',             # Microsoft Teams
        'Zoom.exe',              # Zoom
        'slack.exe',             # Slack
        'Discord.exe',           # Discord
        'spotify.exe',           # Spotify
        'python.exe',            # Python
        'node.exe',              # Node.js
        'git.exe',               # Git
        'docker.exe',            # Docker
        'java.exe',              # Java
        'javaw.exe'              # Java (GUI)
    )
    
    Write-Log -Message "Searching for critical system applications..." -Level INFO
    
    foreach ($appName in $criticalApps) {
        foreach ($basePath in $systemPaths) {
            if (Test-Path $basePath) {
                $found = Get-ChildItem -Path $basePath -Filter $appName -Recurse -ErrorAction SilentlyContinue -Depth 3
                
                foreach ($exe in $found) {
                    $apps += [PSCustomObject]@{
                        Name = $exe.BaseName
                        Path = $exe.FullName
                        Source = 'System'
                    }
                    Write-Log -Message "Found system app: $($exe.Name) at $($exe.DirectoryName)" -Level DEBUG
                }
            }
        }
    }
    
    Write-Log -Message "Found $($apps.Count) system applications" -Level INFO
    
    return $apps
}

function Get-EverythingSearchResults {
    Write-Section "Using Everything CLI for Advanced Search"
    
    $apps = @()
    
    try {
        # Check if Everything CLI (es.exe) is available
        $es = Get-Command es -ErrorAction SilentlyContinue
        
        if (-not $es) {
            $es = Get-Command "$env:ProgramFiles\Everything\es.exe" -ErrorAction SilentlyContinue
        }
        
        if ($es) {
            Write-Log -Message "Everything CLI found. Performing advanced search..." -Level INFO
            
            # Search for all executables on C: drive
            $searchResults = & $es.Source 'c:\ ext:exe' -size-max 500mb 2>&1
            
            if ($LASTEXITCODE -eq 0 -and $searchResults) {
                $resultLines = $searchResults -split "`n" | Where-Object { $_ -match '\.exe$' }
                
                Write-Log -Message "Everything found $($resultLines.Count) executable files" -Level INFO
                
                foreach ($line in $resultLines) {
                    $exePath = $line.Trim()
                    if ($exePath -and (Test-Path $exePath)) {
                        $exe = Get-Item $exePath
                        $apps += [PSCustomObject]@{
                            Name = $exe.BaseName
                            Path = $exe.FullName
                            Source = 'Everything'
                        }
                    }
                }
                
                Write-Log -Message "Processed $($apps.Count) valid executables from Everything search" -Level INFO
            } else {
                Write-Log -Message "Everything search returned no results or failed" -Level WARNING
            }
            
        } else {
            Write-Log -Message "Everything CLI not found. Install from: https://www.voidtools.com/downloads/" -Level WARNING
            Write-Log -Message "Or install via: winget install voidtools.Everything.Cli" -Level INFO
        }
        
    } catch {
        Write-Log -Message "Error using Everything CLI: $($_.Exception.Message)" -Level ERROR
    }
    
    return $apps
}

function Get-StartupTasks {
    Write-Section "Scanning Startup Tasks and Services"
    
    $apps = @()
    
    try {
        # Startup folders
        $startupPaths = @(
            "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
            "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        
        foreach ($path in $startupPaths) {
            if (Test-Path $path) {
                $shortcuts = Get-ChildItem -Path $path -Filter "*.lnk" -ErrorAction SilentlyContinue
                
                foreach ($shortcut in $shortcuts) {
                    try {
                        $shell = New-Object -ComObject WScript.Shell
                        $link = $shell.CreateShortcut($shortcut.FullName)
                        $targetPath = $link.TargetPath
                        
                        if ($targetPath -and (Test-Path $targetPath) -and $targetPath -match '\.exe$') {
                            $apps += [PSCustomObject]@{
                                Name = $shortcut.BaseName
                                Path = $targetPath
                                Source = 'Startup'
                            }
                        }
                    } catch {
                        Write-Log -Message "Failed to process shortcut: $($shortcut.Name)" -Level DEBUG
                    }
                }
            }
        }
        
        # Registry startup entries
        $registryPaths = @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
        )
        
        foreach ($regPath in $registryPaths) {
            if (Test-Path $regPath) {
                $entries = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue
                
                if ($entries) {
                    $entries.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                        $value = $_.Value
                        
                        # Extract executable path from registry value
                        if ($value -match '(?<path>[a-z]:\\[^"]+\.exe)') {
                            $exePath = $matches['path']
                            
                            if (Test-Path $exePath) {
                                $apps += [PSCustomObject]@{
                                    Name = $_.Name
                                    Path = $exePath
                                    Source = 'Registry Startup'
                                }
                            }
                        }
                    }
                }
            }
        }
        
        # Scheduled tasks
        $scheduledTasks = Get-ScheduledTask -ErrorAction SilentlyContinue | 
            Where-Object { $_.State -ne 'Disabled' }
        
        foreach ($task in $scheduledTasks) {
            $taskInfo = $task | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            $actions = $task.Actions | Where-Object { $_.Execute -match '\.exe$' }
            
            foreach ($action in $actions) {
                $exePath = $action.Execute
                
                # Expand environment variables
                $exePath = [System.Environment]::ExpandEnvironmentVariables($exePath)
                
                if (Test-Path $exePath) {
                    $apps += [PSCustomObject]@{
                        Name = $task.TaskName
                        Path = $exePath
                        Source = 'Scheduled Task'
                    }
                }
            }
        }
        
        Write-Log -Message "Found $($apps.Count) startup tasks and scheduled tasks" -Level INFO
        
    } catch {
        Write-Log -Message "Error scanning startup tasks: $($_.Exception.Message)" -Level ERROR
    }
    
    return $apps
}

function Get-InstalledProgramsRegistry {
    Write-Section "Scanning Registry for Installed Programs"
    
    $apps = @()
    
    $registryPaths = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    
    try {
        foreach ($regPath in $registryPaths) {
            $programs = Get-ItemProperty $regPath -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, InstallLocation, DisplayIcon
            
            foreach ($program in $programs) {
                # Try to find executable from install location
                if ($program.InstallLocation -and (Test-Path $program.InstallLocation)) {
                    $exes = Get-ChildItem -Path $program.InstallLocation -Filter "*.exe" -Recurse -ErrorAction SilentlyContinue -Depth 2
                    
                    foreach ($exe in $exes) {
                        $apps += [PSCustomObject]@{
                            Name = $program.DisplayName
                            Path = $exe.FullName
                            Source = 'Registry'
                        }
                    }
                }
                
                # Try to get executable from DisplayIcon
                if ($program.DisplayIcon -and $program.DisplayIcon -match '(?<path>[a-z]:\\[^,]+\.exe)') {
                    $exePath = $matches['path']
                    
                    if (Test-Path $exePath) {
                        $apps += [PSCustomObject]@{
                            Name = $program.DisplayName
                            Path = $exePath
                            Source = 'Registry'
                        }
                    }
                }
            }
        }
        
        Write-Log -Message "Found $($apps.Count) executables from registry" -Level INFO
        
    } catch {
        Write-Log -Message "Error scanning registry: $($_.Exception.Message)" -Level ERROR
    }
    
    return $apps
}

function Get-RunningProcesses {
    Write-Section "Scanning Currently Running Processes"
    
    $apps = @()
    
    try {
        $processes = Get-Process | Where-Object { $_.Path } | Select-Object -Unique Path, Name
        
        foreach ($process in $processes) {
            if (Test-Path $process.Path) {
                $apps += [PSCustomObject]@{
                    Name = $process.Name
                    Path = $process.Path
                    Source = 'Running Process'
                }
            }
        }
        
        Write-Log -Message "Found $($apps.Count) running processes with valid paths" -Level INFO
        
    } catch {
        Write-Log -Message "Error scanning running processes: $($_.Exception.Message)" -Level ERROR
    }
    
    return $apps
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-GPUConfiguration {
    Write-Log -Message "=== Advanced GPU Preference Configuration Script ===" -Level INFO
    Write-Log -Message "Started at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO
    Write-Log -Message "Log file: $LogPath" -Level INFO
    Write-Log -Message "" -Level INFO
    
    # Check admin rights
    Invoke-WithGsudo
    
    if (-not (Test-AdminRights)) {
        Write-Log -Message "Failed to obtain administrator rights. Some operations may fail." -Level ERROR
        return
    }
    
    Write-Log -Message "Running with administrator privileges ✓" -Level SUCCESS
    
    # Collect all applications
    $allApps = @()
    
    # Run all discovery functions
    $allApps += Get-WinGetApps
    $allApps += Get-MicrosoftStoreApps
    $allApps += Get-ScoopApps
    $allApps += Get-ChocolateyApps
    $allApps += Get-SystemApps
    $allApps += Get-StartupTasks
    $allApps += Get-InstalledProgramsRegistry
    $allApps += Get-RunningProcesses
    
    # Use Everything search if not skipped
    if (-not $SkipEverything) {
        $allApps += Get-EverythingSearchResults
    }
    
    # Remove duplicates and sort
    Write-Section "Processing Discovered Applications"
    
    $uniqueApps = $allApps | 
        Sort-Object Path -Unique |
        Sort-Object Source, Name
    
    Write-Log -Message "Total unique applications found: $($uniqueApps.Count)" -Level INFO
    Write-Log -Message "" -Level INFO
    
    # Group by source for reporting
    $groupedApps = $uniqueApps | Group-Object Source
    
    Write-Log -Message "Applications by source:" -Level INFO
    foreach ($group in $groupedApps | Sort-Object Name) {
        Write-Log -Message "  - $($group.Name): $($group.Count) apps" -Level INFO
    }
    Write-Log -Message "" -Level INFO
    
    # Configure GPU preferences
    Write-Section "Configuring GPU Preferences"
    
    $progressCount = 0
    $totalCount = $uniqueApps.Count
    
    foreach ($app in $uniqueApps) {
        $progressCount++
        
        if ($progressCount % 50 -eq 0) {
            $percentComplete = [math]::Round(($progressCount / $totalCount) * 100, 2)
            Write-Log -Message "Progress: $progressCount / $totalCount ($percentComplete%)" -Level INFO
        }
        
        Set-GPUPreference -AppPath $app.Path -AppName "$($app.Name) [$($app.Source)]" -Preference 'Integrated'
    }
    
    # Final summary
    Write-Section "Configuration Summary"
    
    Write-Log -Message "Total applications discovered: $totalCount" -Level INFO
    Write-Log -Message "Successfully configured: $script:SuccessCount" -Level SUCCESS
    Write-Log -Message "Failed to configure: $script:FailureCount" -Level $(if ($script:FailureCount -gt 0) { 'WARNING' } else { 'INFO' })
    Write-Log -Message "Skipped: $script:SkippedCount" -Level INFO
    Write-Log -Message "" -Level INFO
    Write-Log -Message "Completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level INFO
    Write-Log -Message "Full log saved to: $LogPath" -Level INFO
    
    # Export results to CSV
    $csvPath = $LogPath -replace '\.txt$', '.csv'
    $uniqueApps | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log -Message "Application list exported to: $csvPath" -Level INFO
    
    # Open log file
    if (-not $WhatIf) {
        Write-Host "`nPress any key to open the log file..." -ForegroundColor Cyan
        $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        Start-Process notepad $LogPath
    }
}

# ============================================================================
# SCRIPT ENTRY POINT
# ============================================================================

try {
    Start-GPUConfiguration
} catch {
    Write-Log -Message "CRITICAL ERROR: $($_.Exception.Message)" -Level ERROR
    Write-Log -Message "Stack Trace: $($_.ScriptStackTrace)" -Level ERROR
    exit 1
}
