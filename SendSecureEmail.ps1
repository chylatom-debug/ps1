# W zasadzie nic się nie zmienia, dodaję żeby przetestować co i jak.

# ==============================================================================
# SendSecureEmail.ps1
# Opis: Funkcje pomocnicze do wysyłki szyfrowanej poczty S/MIME
#       z walidacją certyfikatów w AD (atrybut userCertificate).
# Autor: Administrator AD
# ==============================================================================

# ------------------------------------------------------------------------------
# KONFIGURACJA — zmień według środowiska
# ------------------------------------------------------------------------------

$MY_EMAIL     = 'jan.kowalski@domena.pl'    # Twój adres (właściciel certyfikatu + kopia BCC)
$FROM_ADDRESS = 'Administrator_AD@domena.pl' # Anonimowy adres wysyłki SMTP
$SMTP_SERVER  = 'war01ex2.domena.pl'
$SMTP_PORT    = 25
$DOMAINS      = @('aaa', 'bbb', 'ccc')      # Domeny AD — kolejność wyszukiwania

# ------------------------------------------------------------------------------
# FUNKCJA: Get-ADUserByEmail
# Wyszukuje użytkownika AD po adresie e-mail we wskazanych domenach.
#
# Strategia (osobne etapy, każdy przeszukuje wszystkie domeny przed przejściem dalej):
#   Etap 1 — atrybut mail           (EmailAddress w AD)
#   Etap 2 — userPrincipalName      (UPN, gdy email == UPN)
#   Etap 3 — proxyAddresses         (np. SMTP:user@domena.pl)
#
# Komunikaty nadpisują się w miejscu — konsola nie jest zaśmiecana dziesiątkami linii.
# Zwraca obiekt ADUser lub $null jeśli nie znaleziono.
# ------------------------------------------------------------------------------
function Get-ADUserByEmail {
    param(
        [Parameter(Mandatory)]
        [string]$EmailAddress
    )

    $proxyValue = "SMTP:$EmailAddress"

    $searchStages = @(
        @{ Label = 'EmailAddress (atrybut mail)'; LDAPFilter = "(mail=$EmailAddress)" },
        @{ Label = 'UPN (userPrincipalName)';     LDAPFilter = "(userPrincipalName=$EmailAddress)" },
        @{ Label = 'ProxyAddresses';              LDAPFilter = "(proxyAddresses=$proxyValue)" }
    )

    foreach ($stage in $searchStages) {

        foreach ($domain in $DOMAINS) {

            Write-Host "`r  Szukam po $($stage.Label) w domenie [$domain]...    " `
                -NoNewline -ForegroundColor DarkCyan

            try {
                $user = Get-ADUser `
                    -Server     $domain `
                    -LDAPFilter $stage.LDAPFilter `
                    -Properties EmailAddress, userPrincipalName, proxyAddresses, userCertificate `
                    -ErrorAction Stop |
                    Select-Object -First 1

                if ($null -ne $user) {
                    Write-Host "`r  [OK] Znaleziono po $($stage.Label) w domenie [$domain]: $($user.SamAccountName)    " `
                        -ForegroundColor Green
                    return $user
                }
            }
            catch {
                Write-Host ''
                Write-Warning "Blad przeszukiwania domeny '$domain' (etap: $($stage.Label)): $_"
            }
        }

        Write-Host "`r  Nie znaleziono po $($stage.Label). Przechodze dalej...    " `
            -ForegroundColor DarkYellow
        Start-Sleep -Milliseconds 300
    }

    Write-Host ''
    Write-Warning "Nie znaleziono '$EmailAddress' w zadnej domenie ($($DOMAINS -join ', ')) po zadnym atrybucie."
    return $null
}

# ------------------------------------------------------------------------------
# FUNKCJA: Get-ValidSMIMECertificate
# Sprawdza atrybut userCertificate uzytkownika AD.
# Zwraca pierwszy wazny certyfikat z EKU "Secure Email" lub $null.
# ------------------------------------------------------------------------------
function Get-ValidSMIMECertificate {
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADUser]$ADUser
    )

    $chosenCertificate = $null
    $now = Get-Date

    if ($null -eq $ADUser.userCertificate -or $ADUser.userCertificate.Count -eq 0) {
        Write-Verbose "Uzytkownik '$($ADUser.EmailAddress)' nie ma certyfikatow w atrybucie userCertificate."
        return $null
    }

    foreach ($rawCert in $ADUser.userCertificate) {

        try {
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]$rawCert
        }
        catch {
            Write-Warning "Nie mozna sparsowac certyfikatu dla '$($ADUser.EmailAddress)': $_"
            continue
        }

        # Sprawdz EKU: Secure Email (OID 1.3.6.1.5.5.7.3.4)
        $validForSecureEmail = $false

        foreach ($extension in $certificate.Extensions) {
            $eku = $extension -as [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]
            if ($null -eq $eku) { continue }

            foreach ($enhancedKeyUsage in $eku.EnhancedKeyUsages) {
                if ($enhancedKeyUsage.FriendlyName -eq 'Secure Email') {
                    $validForSecureEmail = $true
                    break
                }
            }
            if ($validForSecureEmail) { break }
        }

        if (-not $validForSecureEmail) {
            Write-Verbose "Certyfikat '$($certificate.Thumbprint)' -- brak EKU 'Secure Email', pomijam."
            continue
        }

        # Sprawdz waznosc (tolerancja +-5 minut)
        if ($now -gt $certificate.NotBefore.AddMinutes(-5) -and
            $now -lt $certificate.NotAfter.AddMinutes(5)) {

            Write-Verbose "Certyfikat '$($certificate.Thumbprint)' wazny do: $($certificate.NotAfter)."
            $chosenCertificate = $certificate
            break
        }
        else {
            Write-Verbose "Certyfikat '$($certificate.Thumbprint)' poza zakresem waznosci, pomijam."
        }
    }

    return $chosenCertificate
}

# ------------------------------------------------------------------------------
# FUNKCJA: Send-SecureEmail
#
# Wysyla zaszyfrowana wiadomosc S/MIME (AlternateView, enveloped-data).
# Cale body wiadomosci jest zaszyfrowane — brak zalacznika.
# Outlook i inne klienty rozpoznaja wiadomosc automatycznie jako S/MIME.
#
# Parametry:
#   -Credentials  PSCredential — poswiadczenia SMTP ($null = anonimowa wysylka)
#   -SendTo       string       — adres e-mail odbiorcy
#   -Subject      string       — temat wiadomosci
#   -Body         string       — tresc wiadomosci; uzyj here-string @"..."@ dla
#                               wieloliniowych wiadomosci lub wklejonych blokow tekstu
#
# Przyklad:
#   $subject_ = Read-Host "Podaj tytul wiadomosci"
#   $sendto_  = Read-Host "Podaj adres odbiorcy"
#   $tresc = @"
#   Czesc,
#   Twoje konto: xtechniczny01 / P@ssw0rd!
#   "@
#   Send-SecureEmail -Credentials $null -SendTo $sendto_ -Subject $subject_ -Body $tresc
# ------------------------------------------------------------------------------
function Send-SecureEmail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credentials = $null,

        [Parameter(Mandatory)]
        [string]$SendTo,

        [Parameter(Mandatory)]
        [string]$Subject,

        [Parameter(Mandatory = $false)]
        [string]$Body = ''
    )

    # ==========================================================================
    # KROK 1 -- Certyfikat NADAWCY (Twoje konto -- $MY_EMAIL)
    # ==========================================================================

    Write-Host "`n[1/4] Weryfikacja certyfikatu nadawcy ($MY_EMAIL)..." -ForegroundColor Cyan

    $senderADUser = Get-ADUserByEmail -EmailAddress $MY_EMAIL
    if ($null -eq $senderADUser) {
        Write-Error "STOP: Nie znaleziono konta nadawcy '$MY_EMAIL' w AD."
        return
    }

    $senderCert = Get-ValidSMIMECertificate -ADUser $senderADUser
    if ($null -eq $senderCert) {
        Write-Error "STOP: Nadawca '$MY_EMAIL' nie ma waznego certyfikatu S/MIME. Sprawdz atrybut userCertificate w AD."
        return
    }
    Write-Host "  [OK] Certyfikat nadawcy: $($senderCert.Thumbprint)" -ForegroundColor Green

    # ==========================================================================
    # KROK 2 -- Certyfikat ODBIORCY (-SendTo)
    # ==========================================================================

    Write-Host "`n[2/4] Weryfikacja certyfikatu odbiorcy ($SendTo)..." -ForegroundColor Cyan

    $recipientADUser = Get-ADUserByEmail -EmailAddress $SendTo
    if ($null -eq $recipientADUser) {
        Write-Error "STOP: Nie znaleziono konta odbiorcy '$SendTo' w zadnej z domen AD."
        return
    }

    $recipientCert = Get-ValidSMIMECertificate -ADUser $recipientADUser
    if ($null -eq $recipientCert) {
        Write-Error "STOP: Odbiorca '$SendTo' nie ma waznego certyfikatu S/MIME. Sprawdz atrybut userCertificate w AD."
        return
    }
    Write-Host "  [OK] Certyfikat odbiorcy: $($recipientCert.Thumbprint)" -ForegroundColor Green

    # ==========================================================================
    # KROK 3 -- Szyfrowanie S/MIME przez AlternateView
    #
    # AlternateView z typem application/pkcs7-mime powoduje, ze Outlook i inne
    # klienty rozpoznaja wiadomosc jako S/MIME i odszyfrowuja automatycznie.
    #
    # Wysylamy dwie osobne wiadomosci — kazda zaszyfrowana innym kluczem:
    #   - do odbiorcy: zaszyfrowana certyfikatem odbiorcy
    #   - kopia BCC  : zaszyfrowana Twoim certyfikatem (mozesz ja odczytac)
    # ==========================================================================

    Write-Host "`n[3/4] Szyfrowanie S/MIME..." -ForegroundColor Cyan

    Add-Type -AssemblyName System.Security

    [Byte[]]$bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)

    # Wewnetrzna funkcja -- buduje EnvelopedCMS i zwraca AlternateView
    function New-SmimeAlternateView {
        param(
            [Byte[]]$Bytes,
            [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
        )
        try {
            $contentInfo  = New-Object System.Security.Cryptography.Pkcs.ContentInfo (, $Bytes)
            $envelopedCms = New-Object System.Security.Cryptography.Pkcs.EnvelopedCms $contentInfo
            $cmsRecipient = New-Object System.Security.Cryptography.Pkcs.CmsRecipient $Certificate
            $envelopedCms.Encrypt($cmsRecipient)

            [Byte[]]$encrypted = $envelopedCms.Encode()
            $stream  = New-Object System.IO.MemoryStream (, $encrypted)
            $altView = New-Object System.Net.Mail.AlternateView(
                $stream,
                'application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m'
            )
            return $altView
        }
        catch {
            throw "Blad szyfrowania S/MIME: $_"
        }
    }

    Write-Host "  [OK] Gotowe do wysylki." -ForegroundColor Green

    # ==========================================================================
    # KROK 4 -- Wysylka SMTP
    # ==========================================================================

    Write-Host "`n[4/4] Wysylanie ($SMTP_SERVER`:$SMTP_PORT)..." -ForegroundColor Cyan

    $mailClient = $null
    try {
        $mailClient = New-Object System.Net.Mail.SmtpClient($SMTP_SERVER, $SMTP_PORT)
        $mailClient.EnableSsl             = $false  # zmien na $true jesli serwer wymaga STARTTLS
        $mailClient.UseDefaultCredentials = $false

        if ($null -ne $Credentials) {
            $mailClient.Credentials = $Credentials.GetNetworkCredential()
        }

        # --- Wiadomosc DO ODBIORCY ---
        $msgTo         = New-Object System.Net.Mail.MailMessage
        $msgTo.From    = $FROM_ADDRESS
        $msgTo.To.Add($SendTo)
        $msgTo.Subject = $Subject
        $msgTo.AlternateViews.Add(
            (New-SmimeAlternateView -Bytes $bodyBytes -Certificate $recipientCert)
        )
        $mailClient.Send($msgTo)
        Write-Host "  [OK] Wyslano do: $SendTo" -ForegroundColor Green

        # --- KOPIA BCC DO SIEBIE ---
        # Osobna wiadomosc zaszyfrowana Twoim certyfikatem.
        # S/MIME nie pozwala na jedna wiadomosc z dwoma kluczami przez AlternateView,
        # wiec jedyna poprawna metoda to dwie oddzielne wysylki.
        $msgBcc         = New-Object System.Net.Mail.MailMessage
        $msgBcc.From    = $FROM_ADDRESS
        $msgBcc.To.Add($MY_EMAIL)
        $msgBcc.Subject = "[KOPIA] $Subject"
        $msgBcc.AlternateViews.Add(
            (New-SmimeAlternateView -Bytes $bodyBytes -Certificate $senderCert)
        )
        $mailClient.Send($msgBcc)
        Write-Host "  [OK] Kopia BCC do: $MY_EMAIL" -ForegroundColor Green

        Write-Host "`n  Wiadomosc S/MIME wyslana pomyslnie." -ForegroundColor Green
        Write-Host "  Od (SMTP From): $FROM_ADDRESS"         -ForegroundColor Green
    }
    catch {
        Write-Error "BLAD podczas wysylki: $_"
    }
    finally {
        if ($null -ne $mailClient) { $mailClient.Dispose() }
    }
}

# ==============================================================================
# PRZYKLAD UZYCIA
# ==============================================================================
#
# Zaladuj funkcje do biezacej sesji (dot-sourcing):
#   . .\SendSecureEmail.ps1
#
# Nastepnie w dowolnym miejscu skryptu (np. po utworzeniu konta technicznego):
#
#   $subject_ = Read-Host "Podaj tytul wiadomosci"
#   $sendto_  = Read-Host "Podaj adres odbiorcy"
#
#   $tresc = @"
#   Czesc,
#
#   Twoje konto techniczne zostalo utworzone.
#   Login    : xtechniczny01
#   Haslo    : P@ssw0rd!
#   Serwer   : srv-app01.domena.pl
#
#   Pozdrawiam,
#   Administrator AD
#   "@
#
#   Send-SecureEmail `
#       -Credentials $null `
#       -SendTo      $sendto_ `
#       -Subject     $subject_ `
#       -Body        $tresc
#
# ==============================================================================