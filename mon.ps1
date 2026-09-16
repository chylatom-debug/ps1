param(
    [Parameter(Mandatory)]
    [string]$TargetAccount,

    [string]$DCName = $env:COMPUTERNAME,

    [int]$WindowSeconds = 5,

    [int]$MaxLockouts = 5
)

function Get-EventsAroundTime {
    param(
        [datetime]$CenterTime,
        [int]$WindowSec,
        [string]$Computer,
        [string[]]$LogNames
    )

    $start = $CenterTime.AddSeconds(-$WindowSec)
    $end   = $CenterTime.AddSeconds($WindowSec)

    $results = foreach ($log in $LogNames) {
        try {
            Get-WinEvent -ComputerName $Computer -FilterHashtable @{
                LogName   = $log
                StartTime = $start
                EndTime   = $end
            } -ErrorAction Stop |
            Where-Object { $_.Id -ne 4625 -and $_.Id -ne 4740 } |
            Select-Object @{N='Log';E={$log}},
                          TimeCreated,
                          Id,
                          @{N='Message';E={ $_.Message -replace '\s+', ' ' | 
                              ForEach-Object { 
                                  if ($_.Length -gt 300) { $_.Substring(0,300) + '...' } 
                                  else { $_ } 
                              }
                          }}
        } catch {
            # brak zdarzeń w oknie lub brak dostępu do loga — pomijamy
        }
    }
    $results | Sort-Object TimeCreated
}

# ─── Zbierz zdarzenia blokad i nieudanych logowań dla konta ───────────────────

Write-Host "`n=== Szukam zdarzeń dla konta: $TargetAccount na $DCName ===`n" -ForegroundColor Cyan

$lockouts = Get-WinEvent -ComputerName $DCName -FilterHashtable @{
    LogName = 'Security'
    Id      = 4740
} -MaxEvents 50 -ErrorAction Stop |
    Where-Object { $_.Properties[0].Value -eq $TargetAccount } |
    Select-Object -First $MaxLockouts

$failedLogons = Get-WinEvent -ComputerName $DCName -FilterHashtable @{
    LogName = 'Security'
    Id      = 4625
} -MaxEvents 200 -ErrorAction Stop |
    Where-Object { $_.Properties[5].Value -eq $TargetAccount } |
    Select-Object -First ($MaxLockouts * 3)

$triggerEvents = @($lockouts) + @($failedLogons) |
    Sort-Object TimeCreated -Descending |
    Select-Object -First ($MaxLockouts * 4)

if (-not $triggerEvents) {
    Write-Warning "Brak zdarzeń 4625/4740 dla konta '$TargetAccount' na $DCName."
    exit 1
}

Write-Host "Znaleziono $($triggerEvents.Count) zdarzeń wyzwalających." -ForegroundColor Yellow

# ─── Dla każdego zdarzenia — kontekst czasowy ─────────────────────────────────

$logsToSearch = 'Security', 'System', 'Application'

foreach ($evt in $triggerEvents) {

    $evtType = if ($evt.Id -eq 4740) { 'BLOKADA (4740)' } else { 'ZŁE HASŁO (4625)' }

    Write-Host "`n$('─' * 70)" -ForegroundColor DarkGray
    Write-Host "► $evtType | $($evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff'))" -ForegroundColor White

    # Szczegóły samego zdarzenia wyzwalającego
    if ($evt.Id -eq 4740) {
        Write-Host "  Konto       : $($evt.Properties[0].Value)"
        Write-Host "  Zablokowane przez: $($evt.Properties[1].Value)"   # Caller Computer
    } elseif ($evt.Id -eq 4625) {
        Write-Host "  Konto       : $($evt.Properties[5].Value)"
        Write-Host "  Logon Type  : $($evt.Properties[10].Value)"
        Write-Host "  Workstation : $($evt.Properties[13].Value)"
        Write-Host "  Source IP   : $($evt.Properties[19].Value)"
        Write-Host "  Caller PID  : 0x$('{0:X}' -f [int]$evt.Properties[17].Value)  ($($evt.Properties[17].Value))"
        Write-Host "  Caller Proc : $($evt.Properties[18].Value)"
        Write-Host "  Status      : 0x$('{0:X}' -f [int]$evt.Properties[7].Value)"
        Write-Host "  SubStatus   : 0x$('{0:X}' -f [int]$evt.Properties[9].Value)"
    }

    # Zdarzenia w oknie czasowym
    $surrounding = Get-EventsAroundTime `
        -CenterTime  $evt.TimeCreated `
        -WindowSec   $WindowSeconds `
        -Computer    $DCName `
        -LogNames    $logsToSearch

    if ($surrounding) {
        Write-Host "`n  [Kontekst ±${WindowSeconds}s — inne zdarzenia]" -ForegroundColor DarkYellow
        foreach ($s in $surrounding) {
            Write-Host ("  {0}  Log:{1,-12} ID:{2,-6} {3}" -f
                $s.TimeCreated.ToString('HH:mm:ss.fff'),
                $s.Log,
                $s.Id,
                $s.Message
            ) -ForegroundColor Gray
        }
    } else {
        Write-Host "  (brak innych zdarzeń w oknie ±${WindowSeconds}s)" -ForegroundColor DarkGray
    }
}

Write-Host "`n$('═' * 70)" -ForegroundColor Cyan
Write-Host "Gotowe. Przejrzyj zdarzenia System/Application powyżej — szukaj ID zadań, usług, DCOM." -ForegroundColor Cyan
