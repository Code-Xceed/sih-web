# GovShield Sentinel Grid - Process Stopper (PowerShell)

Write-Host "Stopping GovShield background services..." -ForegroundColor Yellow

$ports = @(8000, 3000, 8080)

foreach ($port in $ports) {
    try {
        $pids = (Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue).OwningProcess | Select-Object -Unique
        foreach ($p in $pids) {
            if ($p -and $p -ne 0) {
                Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
                Write-Host "Stopped process $p on Port $port." -ForegroundColor Green
            }
        }
    } catch {}
}

Write-Host "All GovShield background services stopped." -ForegroundColor Green
