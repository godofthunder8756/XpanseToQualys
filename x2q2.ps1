################################################################
#              Cortex Xpanse to Qualys Powershell script       #
#              Author:  Brian Maier                            #
#              Author:  Aidan Ahern (Updated)                  #
#              Version: 0.2                                    #
#              Last Updated: July 30, 2024                     #
################################################################

# Define API endpoints
$XPANSE_BASE_URL = "https://api-pocajg.crtx.us.paloaltonetworks.com/public_api/v1"
$QUALYS_BASE_URL = "https://gateway.qg2.apps.qualys.com"

# Secure credential request
$credentials = Get-Credential -Message "Enter your Qualys credentials"
$qualysApiCreds = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credentials.UserName):$($credentials.getnetworkcredential().password)"))

# Xpanse API credentials
$XPANSE_API_KEY = "ENTER_YOUR_KEY"
$XPANSE_API_ID = "5"

# Headers
$QualysHeaders = @{
    "X-Requested-With" = "QualysPowershell"
    "Authorization" = "Basic $qualysApiCreds"
}

$CSAMHeaders = @{
    "X-Requested-With" = "QualysPowershell"
    "Authorization" = "Basic $qualysApiCreds"
    "Content-Type" = "application/x-www-form-urlencoded"
}

$XpanseHeaders = @{
    "x-xdr-auth-id" = $XPANSE_API_ID
    "Authorization" = $XPANSE_API_KEY
    "Content-Type" = "application/json"
}

$body = @{
    "username"="$($credentials.UserName)"  
    "password"="$($credentials.getnetworkcredential().password)" 
    "token"="true"
}

# Get CSAM token
$tokenResponse = Invoke-RestMethod -Method Post -Uri "$($QUALYS_BASE_URL)/auth" -Body $body
$CSAMToken = $tokenResponse

$CSAMAuthHeaders = @{
    "Authorization" = "Bearer $CSAMToken"
    "Content-Type" = "application/json"
}

function Get-XpanseData {
    param (
        [string]$Endpoint,
        [hashtable]$Body
    )

    $total = 5001
    $searchFrom = 0
    $searchTo = 5000
    $results = @()

    while ($searchFrom -ne $total) {
        $Body.request_data.search_from = $searchFrom
        $Body.request_data.search_to = $searchTo

        Write-Host "Searching from $searchFrom to $searchTo"
        $response = Invoke-RestMethod -Method Post -Uri "$XPANSE_BASE_URL/$Endpoint" -Headers $XpanseHeaders -Body ($Body | ConvertTo-Json -Depth 10)
        
        $total = $response.reply.total_count
        $searchFrom += $response.reply.result_count
        $searchTo += $response.reply.result_count
        $results += $response.reply.assets_internet_exposure
    }

    Write-Host "Job done! Found $($results.Count) items."
    return $results
}

# Get domains from Xpanse
$domainsBody = @{
    request_data = @{
        filters = @(
            @{field="type"; value=@("domain"); operator="in"},
            @{field="externally_detected_providers"; value="on prem"; operator="contains"},
            @{field="has_active_external_services"; value=@("yes"); operator="in"}
        )
        search_from = 0
        search_to = 5000
    }
}

$domains = Get-XpanseData -Endpoint "assets/get_assets_internet_exposure" -Body $domainsBody
$domainNames = $domains.name | Where-Object { $_ -notlike "_*" -and $_ -notmatch "^\*\." }
$domainnames = ($domains.name) -replace 'www.',''| select -Unique
# Process TLDs
$tlds = $domainNames | Select -First 1 |ForEach-Object {
    if ($_ -notlike "*.com") {
        ($_ -split '\.' | Select-Object -Last 3) -join '.'
    } else {
        ($_ -split '\.' | Select-Object -Last 2) -join '.'
    }
} | Select-Object -Unique

#$tlds = $tlds -join ";"     maybe wrong

# Get IPs from Xpanse
$ipsBody = @{
    request_data = @{
        filters = @(
            @{field="business_units_list"; value="Arthur J. Gallagher & Co.(other)"; operator="in"}
        )
        search_from = 0
        search_to = 5000
    }
}

$ipRanges = Get-XpanseData -Endpoint "assets/get_external_ip_address_ranges" -Body $ipsBody

# Process IP data
$xpanseIpData = $ipRanges | Select-Object @{N='first_ip';E={$_.first_ip}}, @{N='last_ip';E={$_.last_ip}}, @{N='ips_count';E={$_.ips_count}}, @{N='tags';E={$_.tags -join ','}}, @{N='annotation';E={$_.annotation}}

# Prepare Qualys EASM profile update
$easmPayload = @{
    name  = "Xpanse"
    includeSeeds = $tlds | Where-Object { $_ -notlike "*mxlogic.net" -and $_ -notlike "*outlook.com*" } | ForEach-Object {
        @{
            seedType = "DOMAIN"
            seedValue = "$($_)"
            seedHeading = "null"
            enumerateSubsidiary = "true"
            horizontalEnumeration = "true"
            seedFilters = @()
        }
    }
    excludeSeeds = @()
}

$jsonPayload = $esamPayload | ConvertTo-Json
Write-Host $jsonPayload

# Uncomment the following lines to actually send the update to Qualys
try {
    $qualysResponse = Invoke-RestMethod -Method Patch -Uri "$($QUALYS_BASE_URL)/easm/v2/profile/Xpanse" -Headers $CSAMAuthHeaders -Body ($easmPayload | ConvertTo-Json -Depth 10)
    Write-Host "Qualys API Response: $($qualysResponse | ConvertTo-Json)"
} catch {
    Write-Host "Failed to update Qualys EASM profile: $_"
    Write-Host "Response: $($_.Exception.Response)"
}
