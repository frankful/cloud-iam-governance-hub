<#
.SYNOPSIS
    本地一键启动：构建并同时运行 api.exe 与 sync-worker.exe。

.DESCRIPTION
    api 内嵌 gitstatus worker；sync-worker 是独立进程，负责消费 asynq 的
    sync 队列（手动同步与工单关单联动都依赖它）。只启动 api 时，同步任务会
    一直停在 PENDING。

.PARAMETER SkipBuild
    跳过 go build，直接启动现有二进制。

.PARAMETER Migrate
    启动前先执行 go run ./cmd/migrate。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/dev-up.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts/dev-up.ps1 -Migrate -SkipBuild
#>
param(
    [switch]$SkipBuild,
    [switch]$Migrate
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$runDir = Join-Path $root ".run"
New-Item -ItemType Directory -Force -Path $runDir | Out-Null

function Stop-ServiceFromPidFile {
    param([string]$Name)

    $pidFile = Join-Path $runDir "$Name.pid"
    if (-not (Test-Path $pidFile)) { return }
    $processId = (Get-Content $pidFile | Select-Object -First 1)
    $existing = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "stopping existing $Name (pid $processId)"
        Stop-Process -Id $processId -Force
        Start-Sleep -Milliseconds 800
    }
    Remove-Item $pidFile -ErrorAction SilentlyContinue
}

# `cmd /c start /b` detaches the service from this script's stdout. Launching
# the exe directly from Start-Process makes the child inherit the parent's
# stdout handle: piping this script (CI, `| Out-String`) then blocks until the
# service exits.
function Start-ServiceProcess {
    param([string]$Name, [string]$Executable)

    $stdout = Join-Path $runDir "$Name.out.log"
    $stderr = Join-Path $runDir "$Name.err.log"
    $exePath = Join-Path $root $Executable
    $processName = [System.IO.Path]::GetFileNameWithoutExtension($Executable)
    $launchThreshold = (Get-Date).AddSeconds(-2)

    $commandLine = '/c start "" /b "' + $exePath + '" > "' + $stdout + '" 2> "' + $stderr + '"'
    Start-Process -FilePath $env:ComSpec -ArgumentList $commandLine `
        -WorkingDirectory $root -WindowStyle Hidden | Out-Null

    $deadline = (Get-Date).AddSeconds(10)
    while ((Get-Date) -lt $deadline) {
        $candidate = Get-Process -Name $processName -ErrorAction SilentlyContinue |
            Where-Object { $_.StartTime -ge $launchThreshold } |
            Sort-Object StartTime -Descending |
            Select-Object -First 1
        if ($candidate) {
            Set-Content -Path (Join-Path $runDir "$Name.pid") -Value $candidate.Id
            Write-Host "started $Name (pid $($candidate.Id))"
            return
        }
        Start-Sleep -Milliseconds 200
    }
    Write-Warning "$Name did not appear within 10s; it may still be starting (check logs)"
}

function Wait-HttpOk {
    param([string]$Uri, [int]$TimeoutSeconds = 30)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 2
            if ($response.StatusCode -eq 200) { return $true }
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    return $false
}

if (-not (Test-Path (Join-Path $root ".env"))) {
    throw ".env not found; copy .env.example and fill DATABASE_URL / REDIS_ADDR / AWS_REGION"
}

if (-not $SkipBuild) {
    Write-Host "building api.exe and sync-worker.exe ..."
    & go build -o api.exe ./cmd/api
    if ($LASTEXITCODE -ne 0) { throw "go build ./cmd/api failed" }
    & go build -o sync-worker.exe ./cmd/sync-worker
    if ($LASTEXITCODE -ne 0) { throw "go build ./cmd/sync-worker failed" }
}

if ($Migrate) {
    Write-Host "applying migrations ..."
    & go run ./cmd/migrate
    if ($LASTEXITCODE -ne 0) { throw "go run ./cmd/migrate failed" }
}

Stop-ServiceFromPidFile -Name "api"
Stop-ServiceFromPidFile -Name "sync-worker"

Start-ServiceProcess -Name "api" -Executable "api.exe"
Start-ServiceProcess -Name "sync-worker" -Executable "sync-worker.exe"

if (Wait-HttpOk -Uri "http://127.0.0.1:8080/health") {
    Write-Host "api healthy: http://127.0.0.1:8080"
} else {
    Write-Warning "api did not become healthy in 30s; check $runDir\api.err.log"
}

if (Wait-HttpOk -Uri "http://127.0.0.1:8081/healthz") {
    Write-Host "sync-worker healthy: http://127.0.0.1:8081/healthz"
} else {
    Write-Warning "sync-worker did not report ready in 30s (AWS_REGION/DATABASE_URL/Redis?); check $runDir\sync-worker.err.log"
}

Write-Host "logs: $runDir"
Write-Host "stop: powershell -ExecutionPolicy Bypass -File scripts/dev-down.ps1"
