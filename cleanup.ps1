#requires -Modules ActiveDirectory
<#
.SYNOPSIS
    AD Cleanup – Faza 1: discovery pustych grup i pustych OU w domenach mbab/ebab/lbab.

.DESCRIPTION
    Skrypt wyłącznie READ-ONLY. Dla każdej domeny pyta PDC Emulator,
    enumeruje:
      - puste grupy: LDAP filter `(!(member=*))` po stronie serwera (szybko),
      - puste OU: enumeracja dzieci w OneLevel scope (brak dobrego LDAP filtra).

    Wyłączenia stałe:
      - kontenery systemowe (Builtin, Domain Controllers, LostAndFound,
        Managed Service Accounts, Microsoft Exchange System Objects,
        Microsoft Exchange Security Groups, Program Data, System,
        Users, Computers, ForeignSecurityPrincipals)
      - obiekty z IsCriticalSystemObject = $true

    Output:
      - empty-groups-<domena>.csv   (per domena)
      - empty-ous-<domena>.csv      (per domena)
      - summary.csv                  (zbiorczo)
      - transcript.log               (log przebiegu)

.PARAMETER Domains
    Tablica FQDN domen. UZUPEŁNIJ przed pierwszym uruchomieniem.

.PARAMETER OutputPath
    Katalog wyjściowy. Domyślnie: <katalog skryptu>\reports\YYYY-MM-DD_HHmm

.EXAMPLE
    .\AD-Cleanup-Phase1-Discover.ps1 `
        -Domains 'mbab.bank.local','ebab.bank.local','lbab.bank.local' `
        -OutputPath D:\AD-Cleanup\reports

.NOTES
    Uprawnienia: read na wszystkich obiektach we wszystkich 3 domenach.
    RODC pomijamy automatycznie (pytamy tylko PDC Emulator).
#>
[CmdletBinding()]
param(
    [string[]]$Domains = @('mbab.<UZUPEŁNIJ>', 'ebab.<UZUPEŁNIJ>', 'lbab.<UZUPEŁNIJ>'),

    [string]$OutputPath = (Join-Path -Path $PSScriptRoot `
        -ChildPath "reports\$(Get-Date -Format 'yyyy-MM-dd_HHmm')")
)

# --- Wykluczenia kontenerów systemowych --------------------------------
# Dopasowanie jako podciąg DN (każdy DN ma separator-przecinek).
$ExcludedContainerSubstrings = @(
    ',CN=Builtin,'
    ',OU=Domain Controllers,'
    ',CN=LostAndFound,'
    ',CN=Managed Service Accounts,'
    ',CN=Microsoft Exchange System Objects,'
    ',CN=Microsoft Exchange Security Groups,'
    ',CN=Program Data,'
    ',CN=System,'
    ',CN=Users,'
    ',CN=Computers,'
    ',CN=ForeignSecurityPrincipals,'
)

function Test-IsInExcludedContainer {
    param([Parameter(Mandatory)][string]$DistinguishedName)
    foreach ($s in $ExcludedContainerSubstrings) {
        if ($DistinguishedName -like "*$s*") { return $true }
    }
    return $false
}

# --- Przygotowanie środowiska ------------------------------------------
$null = New-Item -ItemType Directory -Path $OutputPath -Force
$transcriptPath = Join-Path $OutputPath 'transcript.log'
try { Start-Transcript -Path $transcriptPath -Force | Out-Null } catch { Write-Warning $_ }

Write-Host "=== AD Cleanup – Faza 1: Discovery ===" -ForegroundColor Cyan
Write-Host "Start    : $(Get-Date -Format s)"
Write-Host "Output   : $OutputPath"
Write-Host "Domeny   : $($Domains -join ', ')"

$summary = [System.Collections.Generic.List[psobject]]::new()

foreach ($domain in $Domains) {
    Write-Host "`n--- Domena: $domain ---" -ForegroundColor Yellow

    if ($domain -like '*<UZUPEŁNIJ>*') {
        Write-Warning "FQDN nie uzupełniony dla '$domain' – pomijam."
        continue
    }

    try {
        $pdc = (Get-ADDomain -Identity $domain -ErrorAction Stop).PDCEmulator
        Write-Host "PDC Emulator: $pdc"
    }
    catch {
        Write-Warning "Get-ADDomain('$domain') zawiódł: $($_.Exception.Message)"
        continue
    }

    # --- Puste grupy (LDAP filter po stronie serwera) ------------------
    Write-Host "Szukam pustych grup..."
    try {
        $emptyGroupsRaw = Get-ADGroup -Server $pdc -LDAPFilter '(!(member=*))' `
            -Properties GroupCategory, GroupScope, whenCreated, whenChanged,
                        ManagedBy, Description, info, mail,
                        IsCriticalSystemObject, ObjectGUID, SamAccountName,
                        SID, DistinguishedName -ErrorAction Stop
    }
    catch {
        Write-Warning "Get-ADGroup w '$domain' zawiódł: $($_.Exception.Message)"
        continue
    }

    $emptyGroups = @($emptyGroupsRaw | Where-Object {
        (-not $_.IsCriticalSystemObject) -and
        (-not (Test-IsInExcludedContainer -DistinguishedName $_.DistinguishedName))
    })
    Write-Host "  Pustych grup (po filtracji): $($emptyGroups.Count)" -ForegroundColor Green

    $groupsCsv = Join-Path $OutputPath "empty-groups-$domain.csv"
    $emptyGroups |
        Select-Object @{N='Domain';        E={ $domain }},
                      SamAccountName,
                      Name,
                      @{N='GroupCategory'; E={ [string]$_.GroupCategory }},
                      @{N='GroupScope';    E={ [string]$_.GroupScope }},
                      @{N='IsMailEnabled'; E={ [bool]$_.mail }},
                      mail,
                      whenCreated,
                      whenChanged,
                      @{N='AgeDays';       E={ if ($_.whenChanged) { [int]((Get-Date) - $_.whenChanged).TotalDays } }},
                      @{N='ManagedBy';     E={ $_.ManagedBy }},
                      Description,
                      info,
                      @{N='SID';           E={ $_.SID.Value }},
                      @{N='ObjectGUID';    E={ $_.ObjectGUID.Guid }},
                      DistinguishedName |
        Export-Csv -Path $groupsCsv -Delimiter ';' -Encoding UTF8 -NoTypeInformation

    Write-Host "  CSV: $groupsCsv"

    # --- Puste OU ------------------------------------------------------
    Write-Host "Szukam pustych OU..."
    try {
        $allOUs = Get-ADOrganizationalUnit -Server $pdc -Filter * `
            -Properties whenCreated, whenChanged, gPLink, gPOptions,
                        ProtectedFromAccidentalDeletion, Description,
                        IsCriticalSystemObject, ObjectGUID -ErrorAction Stop
    }
    catch {
        Write-Warning "Get-ADOrganizationalUnit w '$domain' zawiódł: $($_.Exception.Message)"
        continue
    }

    $emptyOUs = foreach ($ou in $allOUs) {
        if ($ou.IsCriticalSystemObject) { continue }
        if (Test-IsInExcludedContainer -DistinguishedName $ou.DistinguishedName) { continue }

        $children = @(Get-ADObject -Server $pdc `
            -SearchBase $ou.DistinguishedName -SearchScope OneLevel `
            -Filter * -ErrorAction SilentlyContinue)

        if ($children.Count -eq 0) { $ou }
    }
    Write-Host "  Pustych OU (po filtracji): $($emptyOUs.Count)" -ForegroundColor Green

    $ousCsv = Join-Path $OutputPath "empty-ous-$domain.csv"
    $emptyOUs |
        Select-Object @{N='Domain';     E={ $domain }},
                      Name,
                      whenCreated,
                      whenChanged,
                      @{N='AgeDays';    E={ if ($_.whenChanged) { [int]((Get-Date) - $_.whenChanged).TotalDays } }},
                      @{N='HasGPOLink'; E={ -not [string]::IsNullOrWhiteSpace($_.gPLink) }},
                      gPLink,
                      ProtectedFromAccidentalDeletion,
                      Description,
                      @{N='ObjectGUID'; E={ $_.ObjectGUID.Guid }},
                      DistinguishedName |
        Export-Csv -Path $ousCsv -Delimiter ';' -Encoding UTF8 -NoTypeInformation

    Write-Host "  CSV: $ousCsv"

    $summary.Add([pscustomobject]@{
        Domain      = $domain
        PDC         = $pdc
        EmptyGroups = $emptyGroups.Count
        EmptyOUs    = $emptyOUs.Count
    })
}

# --- Podsumowanie -------------------------------------------------------
Write-Host "`n=== Podsumowanie ===" -ForegroundColor Cyan
$summary | Format-Table -AutoSize | Out-String | Write-Host

$summary | Export-Csv -Path (Join-Path $OutputPath 'summary.csv') `
    -Delimiter ';' -Encoding UTF8 -NoTypeInformation

Write-Host "Koniec: $(Get-Date -Format s)"
try { Stop-Transcript | Out-Null } catch {}
