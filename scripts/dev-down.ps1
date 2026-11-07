<#
.SYNOPSIS
    停止由 dev-up.ps1 启动的 api.exe 与 sync-worker.exe。
#>

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$runDir = Join-Path $root ".run"

foreach ($name in @("api", "sync-worker")) {
    $pidFile = Join-Path $runDir "$name.pid"
    if (-not (Test-Path $pidFile)) {
        Write-Host "$name is not tracked (no .run/$name.pid)"
        continue
    }
    $processId = (Get-Content $pidFile | Select-Object -First 1)
    $existing = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "stopping $name (pid $processId)"
        Stop-Process -Id $processId -Force
    } else {
        Write-Host "$name (pid $processId) already stopped"
    }
    Remove-Item $pidFile -ErrorAction SilentlyContinue
}
