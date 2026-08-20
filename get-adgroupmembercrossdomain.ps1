function Get-ADGroupMemberCrossDomain {
    <#
    .SYNOPSIS
        Pobiera członków grupy AD niezależnie od domeny, obsługując środowiska multi-domain.
    .DESCRIPTION
        Odpowiednik Get-ADGroupMember -Recursive, który automatycznie wykrywa domenę
        każdego obiektu na podstawie jego DistinguishedName i kieruje zapytania
        do właściwego kontrolera domeny.
    .PARAMETER GroupDN
        DistinguishedName grupy (może być z dowolnej domeny w lesie).
    .PARAMETER Credential
        Opcjonalne poświadczenia. Jeśli nie podane, używa bieżącego kontekstu.
    .EXAMPLE
        Get-ADGroupMemberCrossDomain -GroupDN "CN=grupa,OU=groups,DC=aaa,DC=pl"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$GroupDN,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    # Wyciąga domenę (np. "aaa.pl") z DistinguishedName
    function Get-DomainFromDN {
        param([string]$DN)
        ($DN -replace '^.*?(?=DC=)', '') -replace 'DC=', '' -replace ',', '.'
    }

    # Buduje hashtable z parametrami wspólnymi dla cmdletów AD
    function Get-ADParams {
        param([string]$Server)
        $params = @{ Server = $Server }
        if ($Credential) { $params['Credential'] = $Credential }
        return $params
    }

    # Rekurencyjne pobieranie członków z obsługą zagnieżdżonych grup z innych domen
    function Resolve-GroupMembers {
        param(
            [string]$GroupDN,
            [System.Collections.Generic.HashSet[string]]$Visited
        )

        # Ochrona przed pętlami (grupy cykliczne)
        if (-not $Visited.Add($GroupDN)) {
            Write-Verbose "Pominięto już odwiedzoną grupę: $GroupDN"
            return
        }

        $domain = Get-DomainFromDN -DN $GroupDN
        $adParams = Get-ADParams -Server $domain

        Write-Verbose "Pobieranie członków grupy: $GroupDN (domena: $domain)"

        try {
            $members = Get-ADGroupMember -Identity $GroupDN @adParams -ErrorAction Stop
        }
        catch {
            Write-Warning "Nie można pobrać członków grupy '$GroupDN': $_"
            return
        }

        foreach ($member in $members) {
            $memberDomain = Get-DomainFromDN -DN $member.DistinguishedName
            $memberParams = Get-ADParams -Server $memberDomain

            switch ($member.objectClass) {
                'user' {
                    try {
                        $user = Get-ADUser -Identity $member.DistinguishedName `
                            -Properties SamAccountName, Enabled @memberParams -ErrorAction Stop

                        [PSCustomObject]@{
                            DistinguishedName = $user.DistinguishedName
                            Login             = $user.SamAccountName
                            Enabled           = $user.Enabled
                            Domain            = $memberDomain
                        }
                    }
                    catch {
                        Write-Warning "Nie można pobrać użytkownika '$($member.DistinguishedName)': $_"
                    }
                }
                'group' {
                    # Zagnieżdżona grupa — schodzimy rekurencyjnie
                    Resolve-GroupMembers -GroupDN $member.DistinguishedName -Visited $Visited
                }
                'computer' {
                    Write-Verbose "Pomijam obiekt komputerowy: $($member.DistinguishedName)"
                }
                default {
                    Write-Verbose "Nieobsługiwany typ obiektu '$($member.objectClass)': $($member.DistinguishedName)"
                }
            }
        }
    }

    $visited = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    Resolve-GroupMembers -GroupDN $GroupDN -Visited $visited
}
