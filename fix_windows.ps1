<#
fix_windows.ps1

Executes Windows hardening fixes sent by your YAML → Python engine.

Usage:
  powershell.exe -ExecutionPolicy Bypass -File fix_windows.ps1 -RuleId "WIN-REG-001" -Script "<powershell code>"

Logs stored at:
  C:\SysHardener\logs\fix.log
#>

param (
    [string]$RuleId,
    [string]$Script
)

# Create log directory if not exists
$LogDir = "C:\SysHardener\logs"
$LogFile = "$LogDir\fix.log"

if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

function Log($msg) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp [$RuleId] $msg" | Tee-Object -FilePath $LogFile -Append
}

Log "------------------------------------------------------------"
Log "Fix execution started"

# Temporary script file
$TempScript = "C:\SysHardener\tmp_fix_$RuleId.ps1"
$TempDir = "C:\SysHardener"

if (!(Test-Path $TempDir)) {
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
}

# Write script content into file
Set-Content -Path $TempScript -Value $Script -Force -Encoding UTF8

Log "Executing rule fix script..."

try {
    powershell.exe -ExecutionPolicy Bypass -File $TempScript 2>&1 | 
        ForEach-Object { Log $_ }

    if ($LASTEXITCODE -eq 0) {
        Log "Fix applied successfully."
    } else {
        Log "Fix FAILED with exit code $LASTEXITCODE."
        exit 1
    }
}
catch {
    Log "Exception occurred: $_"
    exit 1
}

# Cleanup temporary script
try {
    Remove-Item -Path $TempScript -Force
    Log "Temporary script cleaned up."
}
catch {
    Log "Failed to remove temp script: $_"
}

Log "Fix execution completed"
Log "------------------------------------------------------------"
exit 0
