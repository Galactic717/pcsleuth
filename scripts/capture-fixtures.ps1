<#
.SYNOPSIS
    Captures redacted real-world fixtures from this PC. Read-only: it never changes a setting.

.DESCRIPTION
    Unelevated it captures the System and Application logs and the battery report.
    Elevated it also captures Diagnostics-Performance events and, for local parser work only,
    raw copies of the SRUM database and the powercfg text reports. Those raw copies go to
    <Out>\private. They hold per-app usage history, so never commit that folder.

    Machine name, user name, user SIDs, battery serial and non-system paths are replaced, then
    the output is searched for the original values and the script fails if any remain.
    The rendered Message is not captured: ToXml() returns only structured event data.

.EXAMPLE
    powershell -NoProfile -File scripts\capture-fixtures.ps1 -Out fixtures
#>
param([Parameter(Mandatory = $true)][string]$Out)

$ErrorActionPreference = 'Stop'
$Utf8 = New-Object Text.UTF8Encoding($false)
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
    IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$Machine = $env:COMPUTERNAME
$User = $env:USERNAME

function Redact-Text([string]$s) {
    $s = $s -replace [regex]::Escape($Machine), 'REDACTED-PC'
    $s = $s -replace [regex]::Escape($User), 'REDACTED-USER'
    $s -replace 'S-1-5-21-[\d-]+', 'S-1-5-21-REDACTED'
}

# Paths and binary names outside the OS and Program Files say what the user runs and works on.
function Redact-Event([string]$xml) {
    $doc = New-Object Xml.XmlDocument
    $doc.PreserveWhitespace = $true
    $doc.LoadXml($xml)
    $ns = New-Object Xml.XmlNamespaceManager($doc.NameTable)
    $ns.AddNamespace('e', 'http://schemas.microsoft.com/win/2004/08/events/event')

    $private = $false
    foreach ($n in $doc.SelectNodes('//e:EventData/e:Data', $ns)) {
        $v = $n.InnerText
        if ($v -match '^[A-Za-z]:\\' -and $v -notmatch '^(?i)C:\\(Windows|ProgramData\\Microsoft)\\') {
            $n.InnerText = 'X:\REDACTED\RedactedApp.exe'
            $private = $true
        }
        if ($v -match '(?i)\\Users\\') { $n.InnerText = 'X:\REDACTED\RedactedApp.exe'; $private = $true }
    }
    if ($private) {
        foreach ($n in $doc.SelectNodes('//e:EventData/e:Data', $ns)) {
            switch ($n.GetAttribute('Name')) {
                'AppName' { $n.InnerText = 'RedactedApp.exe' }
                'PackageFullName' { $n.InnerText = '' }
                'PackageRelativeAppId' { $n.InnerText = '' }
            }
        }
    }
    Redact-Text $doc.OuterXml
}

# Writes one event per line so one fixture can be cited by line and the file stays diffable.
function Save-Events([string]$name, [string]$log, [string]$xpath, [int]$max) {
    try {
        $events = @(Get-WinEvent -LogName $log -FilterXPath $xpath -MaxEvents $max -ErrorAction Stop)
    } catch {
        Write-Host "skip $name : $($_.Exception.Message)"
        return
    }
    $lines = $events | ForEach-Object { Redact-Event $_.ToXml() }
    [IO.File]::WriteAllLines((Join-Path $Out "eventlog\$name.xml"), [string[]]$lines, $Utf8)
    Write-Host "$name : $($events.Count) events"
}

New-Item -ItemType Directory -Force (Join-Path $Out 'eventlog'), (Join-Path $Out 'battery') | Out-Null

function P([string]$provider, [int[]]$ids) {
    $idq = ($ids | ForEach-Object { "EventID=$_" }) -join ' or '
    "*[System[Provider[@Name='$provider'] and ($idq)]]"
}
Save-Events 'power-troubleshooter-1' 'System' (P 'Microsoft-Windows-Power-Troubleshooter' 1) 20
Save-Events 'kernel-power-sleep-resume' 'System' (P 'Microsoft-Windows-Kernel-Power' (42, 107)) 8
Save-Events 'kernel-power-41' 'System' (P 'Microsoft-Windows-Kernel-Power' 41) 3
Save-Events 'kernel-power-105-172' 'System' (P 'Microsoft-Windows-Kernel-Power' (105, 172)) 6
Save-Events 'modern-standby-506-507' 'System' (P 'Microsoft-Windows-Kernel-Power' (506, 507)) 6
Save-Events 'eventlog-6005-6006-6008-6009' 'System' (P 'EventLog' (6005, 6006, 6008, 6009)) 8
Save-Events 'user32-1074' 'System' (P 'User32' 1074) 4
Save-Events 'bugcheck-1001' 'System' (P 'Microsoft-Windows-WER-SystemErrorReporting' 1001) 3
Save-Events 'kernel-processor-power-37' 'System' (P 'Microsoft-Windows-Kernel-Processor-Power' 37) 3
Save-Events 'application-hang-1002' 'Application' (P 'Application Hang' 1002) 6
Save-Events 'application-error-1000' 'Application' (P 'Application Error' 1000) 6
Save-Events 'wer-1001' 'Application' (P 'Windows Error Reporting' 1001) 3
Save-Events 'resource-exhaustion-2004' 'System' (P 'Microsoft-Windows-Resource-Exhaustion-Detector' 2004) 3

# The report is UTF-16 on disk. The fixture keeps that encoding because the parser must handle it.
$tmp = Join-Path $env:TEMP 'pcsleuth-battery-capture.xml'
& powercfg /batteryreport /xml /output $tmp | Out-Null
if ($LASTEXITCODE -eq 0 -and (Test-Path $tmp)) {
    $s = [IO.File]::ReadAllText($tmp)
    $serial = ([regex]'<SerialNumber>([^<]*)</SerialNumber>').Match($s).Groups[1].Value.Trim()
    foreach ($tag in 'ComputerName', 'SystemManufacturer', 'SystemProductName', 'BIOSVersion', 'BIOSDate',
                     'SerialNumber', 'Id', 'Manufacturer', 'ReportGuid') {
        $s = $s -replace "<$tag>[^<]*</$tag>", "<$tag>REDACTED</$tag>"
    }
    [IO.File]::WriteAllText((Join-Path $Out 'battery\battery-report.xml'), (Redact-Text $s), [Text.Encoding]::Unicode)
    Remove-Item $tmp
    Write-Host 'battery report captured'
} else {
    Write-Host 'skip battery report: powercfg failed'
    $serial = ''
}

if ($IsAdmin) {
    Save-Events 'diagnostics-performance-boot' 'Microsoft-Windows-Diagnostics-Performance/Operational' `
        "*[System[(EventID>=100 and EventID<=110)]]" 12
    Save-Events 'diagnostics-performance-shutdown-standby' 'Microsoft-Windows-Diagnostics-Performance/Operational' `
        "*[System[(EventID>=200 and EventID<=203) or (EventID>=300 and EventID<=302)]]" 8

    $private = Join-Path $Out 'private'
    New-Item -ItemType Directory -Force $private | Out-Null
    & powercfg /requests | Out-File -Encoding utf8 (Join-Path $private 'powercfg-requests.txt')
    & powercfg /waketimers | Out-File -Encoding utf8 (Join-Path $private 'powercfg-waketimers.txt')
    & powercfg /srumutil /csv /output (Join-Path $private 'srumutil.csv') 2>&1 |
        Out-File -Encoding utf8 (Join-Path $private 'srumutil-result.txt')
    $sru = Join-Path $env:WINDIR 'System32\sru'
    foreach ($f in Get-ChildItem $sru -File) {
        # esentutl copies a locked ESE file through a temporary shadow copy. The original is untouched.
        & esentutl.exe /y $f.FullName /vss /d (Join-Path $private $f.Name) 2>&1 |
            Out-File -Encoding utf8 -Append (Join-Path $private 'esentutl-result.txt')
    }
    Write-Host "admin-only raw captures in $private (do not commit)"
}

# Fail loudly if the redaction missed anything. private\ is excluded because it is never committed.
$needles = @($Machine, $User) + $(if ($serial) { @($serial) } else { @() })
$leaks = Get-ChildItem $Out -Recurse -File | Where-Object { $_.FullName -notmatch '\\private\\' } | Where-Object {
    $text = [IO.File]::ReadAllText($_.FullName)
    $needles | Where-Object { $text.Contains($_) }
}
if ($leaks) {
    $leaks | ForEach-Object { Write-Host "LEAK $($_.FullName)" }
    throw 'redaction failed: original machine, user or serial value found in output'
}
Write-Host 'redaction check passed'
