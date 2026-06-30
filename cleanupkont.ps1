#requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD Cleanup – Discovery nieaktywnych kont użytkowników (sam raport).

.DESCRIPTION
    Skrypt READ-ONLY. Listuje WŁĄCZONE konta użytkowników, których
    efektywny lastLogon jest starszy niż próg (domyślnie 180 dni)
    lub które nigdy się nie zalogowały.

    Workflow:
      1. LDAP pre-filter na PDC: enabled AND (lastLogonTimestamp <= próg
         OR brak lastLogonTimestamp). Filtr po stronie serwera = szybko.
      2. Pipeline post-filter: whenCreated, ZEW_2_, _A/_a, builtin.
      3. Multi-DC verification: dla każdego kandydata MAX(lastLogon)
         ze wszystkich pisalnych DC. Jeśli MAX świeższy niż próg -> wypada.
         RODC pomijane automatycznie.

    Wyłączenia:
      - konta wyłączone (LDAP)
      - konta utworzone w ostatnich N dni (GraceDays, domyślnie 60)
      - SamAccountName zaczynający się od 'ZEW_2_'
      - SamAccountName kończący się na '_A' lub '_a' (admin)
      - konta wbudowane (IsCriticalSystemObject = $true)

    Output:
      - inactive-users-<domena>.csv  (per domena)
      - summary.csv                   (zbiorczo)
      - transcript.log                (przebieg)

.PARAMETER Domains
    Tablica FQDN domen. UZUPEŁNIJ przed pierwszym uruchomieniem.

.PARAMETER InactiveDays
    Próg nieaktywności w dniach. Domyślnie 180.

.PARAMETER GraceDays
    Wyłącz konta utworzone w ostatnich N dni. Domyślnie 60.

.PARAMETER OutputPath
    Katalog wyjściowy. Domyślnie <katalog skryptu>\reports\YYYY-MM-DD_HHmm

.EXAMPLE
    .\AD-Cleanup-InactiveUsers-Discover.ps1 `
        -Domains 'mbab.bank.local','ebab.bank.local','lbab.bank.local' `
        -OutputPath D:\AD-Cleanup\reports

.NOTES
    Uprawnienia: read na obiektach user we wszystkich 3 domenach.
    Czas wykonania: zwykle kilka minut (zależy od liczby kandydatów
    po pre-filtrze i liczby pisalnych DC).
#>
[CmdletBinding()]
param(
    [string[]]$Domains = @('mbab.<UZUPEŁNIJ>', 'ebab.<UZUPEŁNIJ>', 'lbab.<UZUPEŁNIJ>'),

    [int]$InactiveDays = 180,

    [int]$GraceDays = 60,

    [string]$OutputPath
)

if (-not $OutputPath) {
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $OutputPath = Join-Path $base "reports\$(Get-Date -Format 'yyyy-MM-dd_HHmm')"
}

# --- Wykluczenia po SamAccountName -------------------------------------
$ExcludedSamRegex = @(
    '^ZEW_2_'    # konta zewnętrzne typu 2
    '_[Aa]$'     # admin accounts z sufiksem _A / _a
)

function Test-IsExcludedSam {
    param([string]$Sam)
    foreach ($p in $ExcludedSamRegex) {
        if ($Sam -match $p) { return $true }
    }
    return $false
}

function ConvertFrom-FileTimeSafe {
    param($ft)
    if ($ft -and $ft -gt 0) { [datetime]::FromFileTime([int64]$ft) }
}

# --- Przygotowanie -----------------------------------------------------
$null = New-Item -ItemType Directory -Path $OutputPath -Force
$transcriptPath = Join-Path $OutputPath 'transcript.log'
try { Start-Transcript -Path $transcriptPath -Force | Out-Null } catch { Write-Warning $_ }

$inactiveCutoff   = (Get-Date).AddDays(-$InactiveDays)
$createdCutoff    = (Get-Date).AddDays(-$GraceDays)
$inactiveCutoffFt = $inactiveCutoff.ToFileTime()

Write-Host "=== AD Cleanup – Inactive Users Discovery ===" -ForegroundColor Cyan
Write-Host "Start          : $(Get-Date -Format s)"
Write-Host "InactiveDays   : $InactiveDays  (próg: $inactiveCutoff)"
Write-Host "GraceDays      : $GraceDays  (włączamy konta starsze niż: $createdCutoff)"
Write-Host "Output         : $OutputPath"
Write-Host "Domeny         : $($Domains -join ', ')"

$summary = [System.Collections.Generic.List[psobject]]::new()

foreach ($domain in $Domains) {
    Write-Host "`n--- Domena: $domain ---" -ForegroundColor Yellow

    if ($domain -like '*<UZUPEŁNIJ>*') {
        Write-Warning "FQDN nie uzupełniony dla '$domain' – pomijam."
        continue
    }

    try {
        $pdc = (Get-ADDomain -Identity $domain -ErrorAction Stop).PDCEmulator
        Write-Host "PDC Emulator       : $pdc"
    }
    catch {
        Write-Warning "Get-ADDomain('$domain') zawiódł: $($_.Exception.Message)"
        continue
    }

    # Pisalne DC do multi-DC verification (RODC pomijamy)
    try {
        $writableDCs = @(Get-ADDomainController -Server $pdc `
                            -Filter { IsReadOnly -eq $false } -ErrorAction Stop |
                         Select-Object -ExpandProperty HostName)
        Write-Host "Pisalne DC ($($writableDCs.Count)): $($writableDCs -join ', ')"
    }
    catch {
        Write-Warning "Get-ADDomainController('$domain') zawiódł: $($_.Exception.Message)"
        continue
    }

    # --- Etap 1: LDAP pre-filter na PDC -------------------------------
    Write-Host "Etap 1: LDAP pre-filter na PDC..."
    # enabled AND (lastLogonTimestamp <= próg OR brak lastLogonTimestamp)
    $ldapFilter = "(&" +
                    "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" +
                    "(|(lastLogonTimestamp<=$inactiveCutoffFt)(!(lastLogonTimestamp=*)))" +
                  ")"

    try {
        $candidates = Get-ADUser -Server $pdc -LDAPFilter $ldapFilter `
            -Properties SamAccountName, DisplayName, UserPrincipalName,
                        whenCreated, whenChanged, lastLogonTimestamp,
                        Enabled, Description, Office, Department, Title,
                        Manager, EmailAddress, PasswordLastSet,
                        PasswordNeverExpires, IsCriticalSystemObject,
                        ObjectGUID, DistinguishedName -ErrorAction Stop
    }
    catch {
        Write-Warning "Get-ADUser pre-filter w '$domain' zawiódł: $($_.Exception.Message)"
        continue
    }
    Write-Host "  Wstępnych kandydatów z LDAP    : $($candidates.Count)"

    # --- Etap 2: pipeline post-filter ---------------------------------
    $filtered = @($candidates | Where-Object {
        (-not $_.IsCriticalSystemObject) -and
        ($_.whenCreated -lt $createdCutoff) -and
        (-not (Test-IsExcludedSam -Sam $_.SamAccountName))
    })
    Write-Host "  Po wyłączeniach (created/ZEW_2_/_A/builtin): $($filtered.Count)"

    # --- Etap 3: multi-DC verification --------------------------------
    Write-Host "Etap 3: multi-DC verification lastLogon na $($writableDCs.Count) DC..."
    $i = 0
    $report = foreach ($u in $filtered) {
        $i++
        if ($i % 100 -eq 0) { Write-Host "    ...$i / $($filtered.Count)" }

        $lastLogonMax = $null
        $sourceDC     = $null

        foreach ($dc in $writableDCs) {
            try {
                $perDc = Get-ADUser -Server $dc -Identity $u.ObjectGUID `
                    -Properties lastLogon -ErrorAction Stop

                $dt = ConvertFrom-FileTimeSafe $perDc.lastLogon
                if ($dt -and (-not $lastLogonMax -or $dt -gt $lastLogonMax)) {
                    $lastLogonMax = $dt
                    $sourceDC     = $dc
                }
            }
            catch {
                # cisza – pojedynczy DC może być niedostępny, mamy pozostałe
            }
        }

        $llt = ConvertFrom-FileTimeSafe $u.lastLogonTimestamp
        $effectiveLastLogon = if ($lastLogonMax) { $lastLogonMax } else { $llt }

        # Jeśli MAX(lastLogon) jest świeższy niż próg -> wypada z raportu
        if ($effectiveLastLogon -and $effectiveLastLogon -ge $inactiveCutoff) {
            continue
        }

        [pscustomobject]@{
            Domain                 = $domain
            SamAccountName         = $u.SamAccountName
            DisplayName            = $u.DisplayName
            UserPrincipalName      = $u.UserPrincipalName
            EmailAddress           = $u.EmailAddress
            whenCreated            = $u.whenCreated
            whenChanged            = $u.whenChanged
            LastLogonTimestamp     = $llt
            LastLogonMaxAcrossDCs  = $lastLogonMax
            LastLogonSourceDC      = $sourceDC
            EffectiveLastLogon     = $effectiveLastLogon
            DaysSinceLastLogon     = if ($effectiveLastLogon) {
                                        [int]((Get-Date) - $effectiveLastLogon).TotalDays
                                     } else { 'NEVER' }
            NeverLoggedIn          = (-not $effectiveLastLogon)
            PasswordLastSet        = $u.PasswordLastSet
            PasswordNeverExpires   = $u.PasswordNeverExpires
            Description            = $u.Description
            Department             = $u.Department
            Office                 = $u.Office
            Title                  = $u.Title
            Manager                = $u.Manager
            ObjectGUID             = $u.ObjectGUID.Guid
            DistinguishedName      = $u.DistinguishedName
        }
    }

    Write-Host "  Końcowy raport: $($report.Count)" -ForegroundColor Green

    $csv = Join-Path $OutputPath "inactive-users-$domain.csv"
    $report | Export-Csv -Path $csv -Delimiter ';' -Encoding UTF8 -NoTypeInformation
    Write-Host "  CSV: $csv"

    $summary.Add([pscustomobject]@{
        Domain        = $domain
        PDC           = $pdc
        WritableDCs   = $writableDCs.Count
        LdapCandidates = $candidates.Count
        AfterFilters  = $filtered.Count
        FinalReport   = $report.Count
    })
}

# --- Podsumowanie -------------------------------------------------------
Write-Host "`n=== Podsumowanie ===" -ForegroundColor Cyan
$summary | Format-Table -AutoSize | Out-String | Write-Host

$summary | Export-Csv -Path (Join-Path $OutputPath 'summary.csv') `
    -Delimiter ';' -Encoding UTF8 -NoTypeInformation

Write-Host "Koniec: $(Get-Date -Format s)"
try { Stop-Transcript | Out-Null } catch {}
