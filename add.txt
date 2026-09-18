$rawInput = Read-Host "Podaj login lub loginy (oddzielone !)"
$users = $rawInput -split '!' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

$domainConfig = @(
    @{ Name = 'aaa'; Server = 'aaa.pl'; GroupDN = 'CN=grupaaaa,OU=grupy,DC=aaa,DC=pl' }
    @{ Name = 'bbb'; Server = 'bbb.pl'; GroupDN = 'CN=grupabbb,OU=grupy,DC=bbb,DC=pl' }
    @{ Name = 'ccc'; Server = 'ccc.pl'; GroupDN = 'CN=grupaccc,OU=grupy,DC=ccc,DC=pl' }
)

Write-Host "Dodaję użytkowników $($users -join ', ') do grup domenowych:"

foreach ($user in $users) {
    $found = @()

    foreach ($domain in $domainConfig) {
        try {
            $adUser = Get-ADUser -Filter { SamAccountName -eq $user } -Server $domain.Server -ErrorAction Stop
            if ($adUser) {
                $found += $domain
            }
        }
        catch {
            # brak połączenia z DC lub inna techniczna przyczyna - pomijamy domenę
        }
    }

    if ($found.Count -eq 0) {
        Write-Host "Użytkownik $user nie znaleziony w żadnej z domen"
    }
    elseif ($found.Count -gt 1) {
        $domainNames = ($found | ForEach-Object { $_.Name }) -join ', '
        Write-Host "Użytkownik $user w kilku domenach ($domainNames), skorzystaj z innego skryptu"
    }
    else {
        try {
            Add-ADGroupMember -Identity $found[0].GroupDN -Members $adUser -Server $found[0].Server -ErrorAction Stop
            Write-Host "$user - dodano do grupy domenowej"
        }
        catch {
            Write-Host "$user - błąd podczas dodawania do grupy: $($_.Exception.Message)"
        }
    }
}

Write-Host "Kończę działanie skryptu."
