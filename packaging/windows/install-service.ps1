#Requires -RunAsAdministrator
<#
.SYNOPSIS
Install or remove netgraph-agent as a Windows service.

.DESCRIPTION
The agent already understands the Service Control Manager (svc.Run in
cmd/netgraph-agent/platform_windows.go), so sc.exe can start it like any other
service. The service name is always netgraph-agent: the agent registers under
that exact name, and sc.exe create with another name would start and then
immediately fail.

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
$sc = Join-Path $env:SystemRoot "System32\sc.exe"

function Get-ServiceState {
    $out = & $sc query $service 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
    $line = $out | Select-String "STATE"
    if (-not $line) { return $null }
    if ($line.Line -match 'STATE\s*:\s*\d+\s+(\w+)') { return $Matches[1] }
    return $null
}

if ($Uninstall) {
    $state = Get-ServiceState
    if ($null -eq $state) {
        Write-Host "$service is not installed"
        exit 0
    }
    if ($state -ne "STOPPED") {
        & $sc stop $service | Out-Null
        for ($i = 0; $i -lt 30 -and (Get-ServiceState) -ne "STOPPED"; $i++) {
            Start-Sleep -Seconds 1
        }
    }
    & $sc delete $service | Out-Null
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
if ($null -ne (Get-ServiceState)) {
    throw "$service is already installed; run with -Uninstall first"
}

$command = '"' + $BinPath + '" -server "' + $Server + '" -token-file "' + $TokenFile + '"'
if ($CaFile) {
    if (-not (Test-Path -LiteralPath $CaFile)) { throw "$CaFile not found" }
    $command += ' -ca-file "' + $CaFile + '"'
}
if ($AgentArgs.Count -gt 0) {
    $command += " " + ($AgentArgs -join " ")
}

& $sc create $service start= auto binPath= $command DisplayName= "netgraph agent" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe create $service failed ($LASTEXITCODE)" }
& $sc description $service "Names the program behind this host's sockets for netgraph" | Out-Null
& $sc start $service | Out-Null
if ($LASTEXITCODE -ne 0) { throw "sc.exe start $service failed ($LASTEXITCODE)" }

Write-Host "installed and started $service"
Write-Host "  binary:  $BinPath"
Write-Host "  token:   $TokenFile"
Write-Host "  server:  $Server"
Write-Host ('Change flags by removing and reinstalling, or with: sc.exe config ' + $service + ' binPath= "..."')
Write-Host "Logs go to stderr, which a service has no console for: watch Manage → Host agents on the server."
