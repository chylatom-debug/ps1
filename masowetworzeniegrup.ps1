# ============================================================
# Konfiguracja
# ============================================================
$TxtPath  = "C:\temp\uzytkownicy.txt"
$GroupOU  = "OU=Groups,DC=aaa,DC=pl"
$TargetDC = "aaadc01.aaa.pl"

# ============================================================
# Wyciąga domenę z DN, np. "DC=bbb,DC=pl" -> "bbb.pl"
# ============================================================
function Get-DomainFromDN {
    param([string]$DN)
    ($DN -replace '^.*?(?=DC=)', '') -replace 'DC=', '' -replace ',', '.'
}

# ============================================================
# Import TXT
# ============================================================
$users = Get-Content -Path $TxtPath -Encoding UTF8 | Where-Object { $_.Trim() -ne "" }

foreach ($userDN in $users) {
    $userDN    = $userDN.Trim()
    $sam       = ($userDN -split ',')[0] -replace '^CN=', ''
    $groupName = "D-PA-$sam"
    $userDomain = Get-DomainFromDN -DN $userDN

    Write-Host "Przetwarzam: $sam (domena: $userDomain)" -ForegroundColor Cyan

    # --------------------------------------------------------
    # Pobierz obiekt użytkownika z JEGO domeny
    # --------------------------------------------------------
    try {
        $userObject = Get-ADUser -Identity $userDN `
                                 -Server $userDomain `
                                 -ErrorAction Stop
    }
    catch {
        Write-Warning "  [BŁĄD] Nie można pobrać użytkownika '$userDN' z domeny '$userDomain': $_"
        continue
    }

    # --------------------------------------------------------
    # Utwórz grupę w aaa.pl (jeśli nie istnieje)
    # --------------------------------------------------------
    $existingGroup = Get-ADGroup -Filter "Name -eq '$groupName'" `
                                 -Server $TargetDC `
                                 -ErrorAction SilentlyContinue

    if (-not $existingGroup) {
        try {
            New-ADGroup -Name          $groupName `
                        -GroupScope    DomainLocal `
                        -GroupCategory Security `
                        -Path          $GroupOU `
                        -Server        $TargetDC `
                        -ErrorAction   Stop

            Write-Host "  [OK] Utworzono grupę: $groupName" -ForegroundColor Green
        }
        catch {
            Write-Warning "  [BŁĄD] Nie można utworzyć grupy '$groupName': $_"
            continue
        }
    }
    else {
        Write-Host "  [INFO] Grupa '$groupName' już istnieje — pomijam tworzenie." -ForegroundColor Yellow
    }

    # --------------------------------------------------------
    # Dodaj użytkownika — przekazujemy obiekt, nie DN
    # --------------------------------------------------------
    try {
        Add-ADGroupMember -Identity $groupName `
                          -Members   $userObject `
                          -Server    $TargetDC `
                          -ErrorAction Stop

        Write-Host "  [OK] Dodano '$sam' do grupy '$groupName'" -ForegroundColor Green
    }
    catch {
        Write-Warning "  [BŁĄD] Nie można dodać członka do '$groupName': $_"
    }
}

Write-Host "`nGotowe." -ForegroundColor Cyan
