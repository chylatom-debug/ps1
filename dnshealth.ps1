$OutputFile = "C:\temp\dns.txt"
$LogFile    = "C:\temp\dnslog.log"

# Dwa adresy testowe (zawsze sprawdzane na każdym serwerze)
$TestExternal = "microsoft.com"
$TestInternal = "intranet.domena.pl"

# Grupy serwerów DNS
$DnsGroups = @{
    WKS      = @("8.8.8.8",   "8.8.4.4",   "1.1.1.1",   "1.0.0.1")
    SRV      = @("9.9.9.9",   "149.112.112.112", "208.67.222.222", "208.67.220.220")
    TST      = @("64.6.64.6", "64.6.65.6")
    Internal = @("8.26.56.26","8.20.247.20","185.228.168.9","185.228.169.9",
                 "76.76.19.19","76.223.122.150","94.140.14.14","94.140.15.15")
}

$MaxRetries   = 3
$RetryDelaySec = 3

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Message"
    Add-Content -Path $LogFile -Value $line -Encoding UTF8
}

function Test-DnsServer {
    <#
      Zwraca $true jeśli serwer odpowiedział poprawnie na przynajmniej jeden
      z dwóch rekordów testowych. Próbuje MaxRetries razy z opóźnieniem.
    #>
    param([string]$Server)

    foreach ($name in @($TestExternal, $TestInternal)) {
        $success = $false

        for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
            Write-Log "Test: $Server -> '$name' (próba $attempt/$MaxRetries)"
            $result = Resolve-DnsName -Name $name -Server $Server `
                                      -ErrorAction SilentlyContinue

            if ($result) {
                Write-Log "OK: $Server -> '$name' odpowiedział w próbie $attempt"
                $success = $true
                break
            }

            Write-Log "FAIL: $Server -> '$name' brak odpowiedzi (próba $attempt)" "WARN"
            if ($attempt -lt $MaxRetries) {
                Start-Sleep -Seconds $RetryDelaySec
            }
        }

        # Jeśli chociaż jeden rekord nie przeszedł po 3 próbach – serwer uznany za wadliwy
        if (-not $success) {
            Write-Log "BŁĄD: $Server nie odpowiedział na '$name' po $MaxRetries próbach" "ERROR"
            return $false
        }
    }

    return $true
}

#główna logika

Write-Log "=== Start DNS Health Check ==="

# Sprawdź katalog wyjściowy
foreach ($path in @($OutputFile, $LogFile)) {
    $dir = Split-Path $path
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Log "Utworzono katalog: $dir"
    }
}

$failedServers = @{ WKS = @(); SRV = @(); TST = @(); Internal = @() }

foreach ($group in $DnsGroups.Keys) {
    Write-Log "--- Sprawdzanie grupy: $group ---"
    foreach ($srv in $DnsGroups[$group]) {
        $ok = Test-DnsServer -Server $srv
        if (-not $ok) {
            $failedServers[$group] += $srv
            Write-Log "Serwer $srv (grupa $group) dodany do listy błędów" "WARN"
        }
    }
}

$wksFailed      = $failedServers.WKS.Count
$srvFailed      = $failedServers.SRV.Count
$internalFailed = $failedServers.Internal.Count
$tstFailed      = $failedServers.TST.Count

Write-Log "Podsumowanie: WKS=$wksFailed SRV=$srvFailed Internal=$internalFailed TST=$tstFailed"

# -----------------------------------------------------------------
# Logika statusu
#
#  status=0  – brak błędów
#  status=1  – "ostrzeżenie":
#               • 1 z 2  TST serwerów wadliwy
#               • 1 z 4  SRV serwerów wadliwy
#               • 1 z 4  WKS serwerów wadliwy
#               • 1 z 8  Internal serwerów wadliwy (analogia, brak osobnego progu)
#  status=2  – "krytyczny":
#               • >=2 WKS serwerów wadliwych
#               • >=2 SRV serwerów wadliwych
# -----------------------------------------------------------------

$status = 0

# Najpierw sprawdź krytyczne (status=2 ma priorytet)
if ($wksFailed -ge 2 -or $srvFailed -ge 2) {
    $status = 2
}
elseif ($tstFailed -ge 1 -or $wksFailed -eq 1 -or $srvFailed -eq 1 -or $internalFailed -ge 1) {
    $status = 1
}

Write-Log "Wynikowy status: $status"

# -----------------------------------------------------------------
# Zapis do pliku dns.txt
# -----------------------------------------------------------------
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$wksServersStr      = ($failedServers.WKS      -join ",")
$srvServersStr      = ($failedServers.SRV      -join ",")
$internalServersStr = ($failedServers.Internal -join ",")
$tstServersStr      = ($failedServers.TST      -join ",")

$content = @"
wks_failed=$wksFailed
srv_failed=$srvFailed
internal_failed=$internalFailed
tst_failed=$tstFailed
status=$status
timestamp=$timestamp
wks_servers=$wksServersStr
srv_servers=$srvServersStr
internal_servers=$internalServersStr
tst_servers=$tstServersStr
"@

Set-Content -Path $OutputFile -Value $content -Encoding UTF8
Write-Log "Zapisano wyniki do $OutputFile"
Write-Log "=== Koniec DNS Health Check ==="
