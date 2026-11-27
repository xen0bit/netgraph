#Requires -RunAsAdministrator
<#
.SYNOPSIS
Install or remove netgraph-agent as a Windows service.

.DESCRIPTION
The agent already understands the Service Control Manager (svc.Run in
cmd/netgraph-agent/platform_windows.go), so sc.exe can start it like any other
service. It is installed as netgraph-agent, the name the agent gives the
Service Control Manager.

Run from an elevated PowerShell prompt. The default service account is
LocalSystem, which can read other users' processes; the agent never changes
the Windows firewall.

.PARAMETER BinPath
Path to netgraph-agent.exe.

.PARAMETER TokenFile
File holding the agent token (the server's -agent-token-file value). Keep it
readable by Administrators and SYSTEM only, not by ordinary users.

.PARAMETER Server
The netgraph server's URL.

.PARAMETER CaFile
Optional PEM CA bundle for a server with a private CA.

.PARAMETER AgentArgs
Extra netgraph-agent flags, for example -name office-pc -interval 5s.

.PARAMETER Uninstall
Stop and delete the service. The token file and binary are left alone.

.EXAMPLE
.\install-service.ps1 -Server https://netgraph.lan:8443 `
  -TokenFile C:\ProgramData\netgraph\agent.token

.EXAMPLE
.\install-service.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$BinPath = "$env:ProgramFiles\netgraph\netgraph-agent.exe",
    [string]$TokenFile = "$env:ProgramData\netgraph\agent.token",
    [string]$Server = "https://netgraph.lan:8443",
    [string]$CaFile = "",
    [string[]]$AgentArgs = @(),
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$service = "netgraph-agent"

# The service's command line is handed to the Service Control Manager as one
# string by New-Service. sc.exe would need it as a native argument, and Windows
# PowerShell 5.1 does not escape the quotes inside one: a path under
# "C:\Program Files" would reach sc.exe broken apart.
function Quote([string]$s) {
    if ($s -match '"') { throw "a double quote can't be part of a path or URL here: $s" }
    return '"' + $s + '"'
}

$existing = Get-Service -Name $service -ErrorAction SilentlyContinue

if ($Uninstall) {
    if ($null -eq $existing) {
        Write-Host "$service is not installed"
        exit 0
    }
    if ($existing.Status -ne "Stopped") {
        Stop-Service -Name $service -Force
        $existing.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
    # Remove-Service needs PowerShell 6; sc.exe delete takes only the name.
    & (Join-Path $env:SystemRoot "System32\sc.exe") delete $service | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "sc.exe delete $service failed ($LASTEXITCODE)" }
    Write-Host "removed $service"
    exit 0
}

if (-not (Test-Path -LiteralPath $BinPath)) {
    throw "$BinPath not found: pass -BinPath"
}
if (-not (Test-Path -LiteralPath $TokenFile)) {
    throw "$TokenFile not found: write the agent token there, or pass -TokenFile"
}
if ($null -ne $existing) {
    throw "$service is already installed; run with -Uninstall first"
}

$command = (Quote $BinPath) + " -server " + (Quote $Server) + " -token-file " + (Quote $TokenFile)
if ($CaFile) {
    if (-not (Test-Path -LiteralPath $CaFile)) { throw "$CaFile not found" }
    $command += " -ca-file " + (Quote $CaFile)
}
foreach ($a in $AgentArgs) {
    $command += " " + $(if ($a -match '\s') { Quote $a } else { $a })
}

New-Service -Name $service -BinaryPathName $command -DisplayName "netgraph agent" `
    -Description "Names the program behind this host's sockets for netgraph" `
    -StartupType Automatic | Out-Null
Start-Service -Name $service

Write-Host "installed and started $service"
Write-Host "  binary:  $BinPath"
Write-Host "  token:   $TokenFile"
Write-Host "  server:  $Server"
Write-Host "Change flags by running with -Uninstall and installing again."
Write-Host "Logs go to stderr, which a service has no console for: watch Manage -> Host agents on the server."
