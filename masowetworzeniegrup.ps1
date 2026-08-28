# ============================================================
# Konfiguracja
# ============================================================
$TxtPath   = "C:\temp\uzytkownicy.txt"
$GroupOU   = "OU=Groups,DC=aaa,DC=pl"
$TargetDC  = "aaadc01.aaa.pl"

# ============================================================
# Import TXT
# ============================================================
$users = Get-Content -Path $TxtPath -Encoding UTF8 | Where-Object { $_.Trim() -ne "" }

foreach ($userDN in $users) {
    $userDN = $userDN.Trim()

    $sam       = ($userDN -split ',')[0] -replace '^CN=', ''
    $groupName = "D-PA-$sam"

    Write-Host "Przetwarzam: $sam" -ForegroundColor Cyan

    # --------------------------------------------------------
    # Utwórz grupę (jeśli nie istnieje)
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
    # Dodaj użytkownika do grupy
    # --------------------------------------------------------
    try {
        Add-ADGroupMember -Identity $groupName `
                          -Members   $userDN `
                          -Server    $TargetDC `
                          -ErrorAction Stop

        Write-Host "  [OK] Dodano '$userDN' do grupy '$groupName'" -ForegroundColor Green
    }
    catch {
        Write-Warning "  [BŁĄD] Nie można dodać członka do '$groupName': $_"
    }
}

Write-Host "`nGotowe." -ForegroundColor Cyan
