<#
.SYNOPSIS
    Launches the Secure Access Lab live demo: starts the real WebSocket
    bridge (sim/protocol/uds_server.py) against a real VirtualECU, then
    opens the ECU Monitor dashboard connected to it.

.DESCRIPTION
    This does NOT use any dummy/simulated data in the browser. The server
    started here boots an actual VirtualECU + DiagnosticClient pair
    (sim/core/ecu.py, sim/protocol/client.py) and streams real UDS traffic,
    session state, and audit log entries to the dashboard over
    ws://localhost:8765.

.USAGE
    powershell -ExecutionPolicy Bypass -File .\start_demo.ps1
    (or simply double-click start_demo.bat)
#>

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$venvDir    = Join-Path $root ".venv"
$venvPython = Join-Path $venvDir "Scripts\python.exe"
$port       = 8765

function Test-PortOpen([int]$p) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect("127.0.0.1", $p, $null, $null)
        $ok = $iar.AsyncWaitHandle.WaitOne(300, $false)
        if ($ok) { $client.EndConnect($iar) }
        $client.Close()
        return $ok
    } catch {
        return $false
    }
}

# ── 1. Ensure a virtual environment with dependencies exists ────────────────
if (-not (Test-Path $venvPython)) {
    Write-Host "[start_demo] No .venv found — creating one..." -ForegroundColor Yellow
    $systemPython = (Get-Command python -ErrorAction SilentlyContinue)
    if (-not $systemPython) {
        Write-Host "[start_demo] ERROR: Python not found on PATH. Install Python 3.11+ and re-run." -ForegroundColor Red
        exit 1
    }
    python -m venv $venvDir
}

Write-Host "[start_demo] Checking dependencies (cryptography, websockets, pytest)..." -ForegroundColor Cyan
& $venvPython -m pip install --quiet --upgrade pip
& $venvPython -m pip install --quiet -r (Join-Path $root "requirements.txt")

# ── 2. Start (or reuse) the WebSocket bridge / VirtualECU server ────────────
if (Test-PortOpen $port) {
    Write-Host "[start_demo] A server is already listening on ws://localhost:$port — reusing it." -ForegroundColor Yellow
} else {
    Write-Host "[start_demo] Starting VirtualECU + WebSocket bridge on ws://localhost:$port ..." -ForegroundColor Cyan
    Start-Process -FilePath $venvPython `
        -ArgumentList "-m", "sim.protocol.uds_server" `
        -WorkingDirectory $root `
        -WindowStyle Normal

    Write-Host "[start_demo] Waiting for server to come up..." -ForegroundColor Cyan
    $attempts = 0
    while (-not (Test-PortOpen $port) -and $attempts -lt 20) {
        Start-Sleep -Milliseconds 300
        $attempts++
    }
    if (-not (Test-PortOpen $port)) {
        Write-Host "[start_demo] WARNING: server did not respond on port $port yet. Check the new console window for errors." -ForegroundColor Yellow
    }
}

# ── 3. Open the dashboard, pointed at the live server ────────────────────────
$dashboard = Join-Path $root "gui\secure_access_monitor.html"
if (Test-Path $dashboard) {
    Write-Host "[start_demo] Opening dashboard: $dashboard" -ForegroundColor Green
    Start-Process $dashboard
} else {
    Write-Host "[start_demo] ERROR: dashboard not found at $dashboard" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[start_demo] Demo is live." -ForegroundColor Green
Write-Host "  Server window : real VirtualECU + WebSocket bridge (leave it running)"
Write-Host "  Dashboard     : gui\secure_access_monitor.html (connected to ws://localhost:$port)"
Write-Host "  To stop       : close the server console window, or Ctrl+C inside it"
Write-Host "  Guide         : see UserHelp.md for how to use the dashboard controls"
Write-Host ""
