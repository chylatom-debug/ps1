function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('Info','OK','Warn','Error')]
        [string]$Type = 'Info'
    )
    switch ($Type) {
        'Info'  { Write-Host "[*] $Message" -ForegroundColor Cyan }
        'OK'    { Write-Host "[+] $Message" -ForegroundColor Green }
        'Warn'  { Write-Host "[!] $Message" -ForegroundColor Yellow }
        'Error' { Write-Host "[-] $Message" -ForegroundColor Red }
    }
}

function Invoke-EntraIDMigration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Login
    )

    $domains = @('eee', 'eee', 'eee')
    $adUser = $null
    $targetDomain = $null

    # --- 1. Pobranie loginu ---
    if ([string]::IsNullOrWhiteSpace($Login)) {
        do {
            $Login = Read-Host "Podaj login lub domena\login (lub 'exit')"
            if ($Login -eq 'exit') { Write-Status "Przerwano." -Type Info; return }
            if ([string]::IsNullOrWhiteSpace($Login)) { Write-Status "Login nie może być pusty." -Type Warn }
        } while ([string]::IsNullOrWhiteSpace($Login))
    }

    # --- 2. Wyszukanie konta ---
    if ($Login -match '^(?<domain>[^\\]+)\\(?<sam>[^\\]+)$') {
        # Format domena\login — szukamy bezpośrednio
        $targetDomain = $Matches['domain']
        $sam = $Matches['sam']

        if ($targetDomain -notin $domains) {
            Write-Status "Domena '$targetDomain' nie jest obsługiwana ($($domains -join ', '))." -Type Error
            return
        }

        Write-Status "Szukam konta '$sam' w domenie $targetDomain..."
        try {
            $adUser = Get-ADUser -Identity $sam -Server $targetDomain `
                -Properties UserPrincipalName, EmailAddress, extensionAttribute1 -ErrorAction Stop
            Write-Status "Konto znalezione w domenie: $targetDomain" -Type OK
        }
        catch {
            Write-Status "Nie znaleziono konta '$sam' w domenie '$targetDomain'." -Type Error
            return
        }
    }
    else {
        # Szukamy rekurencyjnie we wszystkich domenach
        $found = @()
        Write-Status "Szukam konta '$Login' w domenach: $($domains -join ', ')..."

        foreach ($d in $domains) {
            try {
                $u = Get-ADUser -Identity $Login -Server $d `
                    -Properties UserPrincipalName, EmailAddress, extensionAttribute1 -ErrorAction Stop
                Write-Status "Znaleziono w: $d" -Type OK
                $found += [PSCustomObject]@{ Domain = $d; User = $u }
            }
            catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                Write-Status "Brak w: $d" -Type Info
            }
            catch {
                Write-Status "Błąd przy odpytywaniu ${d}: $($_.Exception.Message)" -Type Error
            }
        }

        if ($found.Count -eq 0) {
            Write-Status "Konto '$Login' nie istnieje w żadnej domenie." -Type Error
            return
        }

        if ($found.Count -eq 1) {
            $targetDomain = $found[0].Domain
            $adUser = $found[0].User
        }
        else {
            $domainList = ($found | ForEach-Object { $_.Domain }) -join ', '
            Write-Status "Konto istnieje w wielu domenach ($domainList). Wskaż domenę." -Type Warn

            do {
                $pick = Read-Host "Podaj domenę ($domainList) lub 'exit'"
                if ($pick -eq 'exit') { Write-Status "Przerwano." -Type Info; return }
                if ($pick -notin $domains) { Write-Status "Nieprawidłowa domena." -Type Warn; continue }
                $match = $found | Where-Object { $_.Domain -eq $pick }
                if ($match) {
                    $targetDomain = $match.Domain
                    $adUser = $match.User
                    break
                }
                Write-Status "Konto nie zostało znalezione w domenie '$pick'." -Type Warn
            } while ($true)
        }
    }

    # --- 3. Podsumowanie ---
    $sam = $adUser.SamAccountName
    Write-Host ""
    Write-Status "Konto: $sam @ $targetDomain"
    Write-Host "  UPN      : $($adUser.UserPrincipalName)"
    Write-Host "  Email    : $($adUser.EmailAddress ?? '<brak>')"
    Write-Host "  ExtAttr1 : $($adUser.extensionAttribute1 ?? '<brak>')"
    Write-Host ""

    # --- 4. UPN ---
    $base = if ($sam -match '^(.+)_A$') { $Matches[1] } else { $sam }
    $upnDomain = if ($sam -like 'ZEW_2_*') { 'partners.eee.pl' } else { 'eee.pl' }
    $expectedUpn = "$base-adm@$upnDomain"

    if ($adUser.UserPrincipalName -eq $expectedUpn) {
        Write-Status "UPN OK: $expectedUpn" -Type OK
    }
    else {
        Write-Status "UPN: $($adUser.UserPrincipalName) -> $expectedUpn" -Type Warn
        try {
            Set-ADUser -Identity $adUser.DistinguishedName -Server $targetDomain `
                -UserPrincipalName $expectedUpn -ErrorAction Stop
            Write-Status "UPN zmieniony." -Type OK
        }
        catch {
            Write-Status "Błąd zmiany UPN: $($_.Exception.Message)" -Type Error
            return
        }
    }

    # --- 5. Email = UPN ---
    if ($adUser.EmailAddress -eq $expectedUpn) {
        Write-Status "Email OK: $expectedUpn" -Type OK
    }
    else {
        $oldEmail = $adUser.EmailAddress ?? '<brak>'
        Write-Status "Email: $oldEmail -> $expectedUpn" -Type Warn
        try {
            Set-ADUser -Identity $adUser.DistinguishedName -Server $targetDomain `
                -EmailAddress $expectedUpn -ErrorAction Stop
            Write-Status "Email zmieniony." -Type OK
        }
        catch {
            Write-Status "Błąd zmiany email: $($_.Exception.Message)" -Type Error
            return
        }
    }

    # --- 6. ExtensionAttribute1 ---
    $ext = $adUser.extensionAttribute1

    if ($ext -eq '1') {
        Write-Status "ExtensionAttribute1 = 1 — konto gotowe." -Type OK
    }
    else {
        $old = if ([string]::IsNullOrWhiteSpace($ext)) { '<brak>' } else { $ext }
        Write-Status "ExtensionAttribute1: $old -> 1" -Type Warn
        try {
            Set-ADUser -Identity $adUser.DistinguishedName -Server $targetDomain `
                -Replace @{ extensionAttribute1 = '1' } -ErrorAction Stop
            Write-Status "ExtensionAttribute1 zmieniony." -Type OK
        }
        catch {
            Write-Status "Błąd zmiany ExtensionAttribute1: $($_.Exception.Message)" -Type Error
            return
        }
    }

    Write-Host ""
    Write-Status "Zakończono." -Type Info
}

# Uruchomienie interaktywne (pomijane przy dot-source)
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-EntraIDMigration
}
