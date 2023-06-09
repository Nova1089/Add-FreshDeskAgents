<#
This script takes a CSV file with agents and adds them into FreshDesk.

Fill out a CSV with the following headers:
Full Name
Email
License
    Accepts "Full Time" or "Occasional".
Scope
    Accepts "Global", "Group", or "Restricted".
Groups
    Accepts one or more existing groups, comma separated. May also be left empty.
Roles
    Accepts one or more existing roles, comma separated. May also be left empty.

After that, just run script and follow the prompts.
#>

# functions
function Initialize-ColorScheme
{
    $script:successColor = "Green"
    $script:infoColor = "DarkCyan"
    $script:warningColor = "Yellow"
    $script:failColor = "Red"    
}

function Show-Introduction
{
    Write-Host "This script takes a CSV file with agents and adds them into FreshDesk." -ForegroundColor $infoColor
    Read-Host "Press Enter to continue"
}

function Show-Tutorial
{
    Write-Host ("Please fill out a CSV with the following headers: `n" +
        "Full Name `n" +
        "Email `n" +
        "License `n" +
        "    Accepts `"Full Time`" or `"Occasional`" `n" +
        "Scope `n" +
        "    Accepts `"Global`", `"Group`", or `"Restricted`" `n" +
        "Groups `n" +
        "    Accepts one or more existing groups, comma separated. May also be left empty. `n" +
        "Roles `n" +
        "    Accepts one or more existing roles, comma separated. May also be left empty. `n") -ForegroundColor $infoColor
}

function Get-ConnectionInfo
{
    $baseUrl = Prompt-Url
    $myProfileUrl = "$baseUrl/api/v2/agents/me"
    $encodedKey = Get-EncodedApiKey
    $headers = @{
        Authorization = "Basic $encodedKey"      
    }

    do
    {
        try
        {
            Invoke-RestMethod -Method "Get" -Uri $myProfileUrl -Headers $headers -ErrorVariable "responseError" | Out-Null
        }
        catch
        {
            Write-Warning "API request for your profile returned an error:`n$($responseError[0].Message)"

            switch ([int]$_.Exception.Response.StatusCode)
            {
                404
                {
                    Write-Warning "URL is invalid. Please enter a valid FreshDesk URL (i.e., https://company-name.freshdesk.com)"
                    $baseUrl = Prompt-Url
                    $myProfileUrl = "$baseUrl/api/v2/agents/me"
                }
                401
                {
                    Write-Warning "API key invalid or lacks permissions."
                    $encodedKey = Get-EncodedApiKey
                    $headers = @{
                        Authorization = "Basic $encodedKey"      
                    }
                }
                default
                {
                    # If the error can't be resolved by fixing URL or API key, we'll have to exit.
                    exit
                }
            }
            continue
        }
        $isValidConnection = $true
    }
    while (-not($isValidConnection))

    return [PSCustomObject]@{
        BaseUrl = $baseUrl
        EncodedKey = $encodedKey
    }
}

function Prompt-Url
{
    do
    {
        $url = Read-Host "Enter your FreshDesk URL (i.e., https://company-name.freshdesk.com)"
        $validUrl = $url -match '^\s*https:\/\/.*\.freshdesk\.\w{2,}\s*$'

        if (-not($validUrl))
        {
            Write-Warning "URL is invalid. Please enter a valid FreshDesk URL (i.e., https://company-name.freshdesk.com)"
        }
    }
    while (-not($validUrl))

    return $url.Trim()
}

function Get-EncodedApiKey
{

    $secureString = Read-Host "Please enter your API key" -AsSecureString
    $psCredential = Convert-SecureStringToPsCredential $secureString
    # Append :X because FreshDesk expects that. Could be X or anything else.
    return ConvertTo-Base64 ($psCredential.GetNetworkCredential().Password + ":X")
    
}

function Convert-SecureStringToPsCredential($secureString)
{
    # just passing "null" for username, because username will not be used
    return New-Object System.Management.Automation.PSCredential("null", $secureString)
}

function ConvertTo-Base64($text)
{
    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($text))
}

function Get-ExpectedHeaders
{
    return @("Full Name", "Email", "License", "Scope", "Groups", "Roles")
}

function Get-AllTicketScopeIds
{
    return @{
        Global     = 1
        Group      = 2
        Restricted = 3
    }
}

function Get-AllGroupIds($url, $encodedKey)
{
    $url = "$url/api/v2/groups"
    $headers = @{
        Authorization = "Basic $encodedKey"      
    }

    $groups = SafelyInvoke-RestMethod -Method "Get" -Uri $url -Headers $headers
    $lookupTable = @{}
    foreach ($group in $groups)
    {
        $lookupTable.Add($group.name, $group.id)
    }

    return $lookupTable
}

function SafelyInvoke-RestMethod($method, $uri, $headers, $body)
{
    try
    {
        $response = Invoke-RestMethod -Method $method -Uri $uri -Headers $headers -Body $body -ErrorVariable "responseError"
    }
    catch
    {
        Write-Host $responseError[0].Message -ForegroundColor $failColor
        # exit
    }

    return $response
}

function Get-AllRoleIds($url, $encodedKey)
{
    $url = "$url/api/v2/roles"
    $headers = @{
        Authorization = "Basic $encodedKey"      
    }

    $roles = SafelyInvoke-RestMethod -Method "Get" -Uri $url -Headers $headers
    $lookupTable = @{}
    foreach ($role in $roles)
    {
        $lookupTable.Add($role.name, $role.id)
    }

    return $lookupTable
}

function Import-AgentData($expectedHeaders, $allTicketScopeIds, $allGroupIds, $allRoleIds)
{
    do
    {
        $importedCsv = Prompt-Csv $expectedHeaders
        $agentRecords = Parse-AgentRecords $importedCsv 
        $isValidAgentData = Validate-AgentData $agentRecords $allTicketScopeIds $allGroupIds $allRoleIds
    }
    while (-not($isValidAgentData))

    return $agentRecords
}

function Prompt-Csv($expectedHeaders)
{
    do
    {
        $path = Read-Host "Enter path to CSV"
        $path = $path.Trim('"')
        $extension = [IO.Path]::GetExtension($path)

        if ($extension -ne '.csv')
        {
            Write-Warning "File type is $extension. Please enter a CSV."
            $keepGoing = $true
            continue
        }

        try
        {
            $records = Import-CSV -Path $path -ErrorAction SilentlyContinue
        }
        catch
        {
            Write-Warning "CSV not found."
            $keepGoing = $true
            continue
        }

        if ($records.Count -eq 0)
        {
            Write-Warning "CSV is empty."
            $keepGoing = $true
            continue
        }

        $hasExpectedHeaders = Validate-CsvHeaders -ImportedCsv $records -ExpectedHeaders $expectedHeaders
        if (-not($hasExpectedHeaders))
        {
            $keepGoing = $true
            continue
        }
        
        $keepGoing = $false
    }
    while ($keepGoing)

    Write-Host "CSV was found and validated." -ForegroundColor $successColor

    return $records
}

function Validate-CsvHeaders($importedCsv, $expectedHeaders)
{
    $hasExpectedHeaders = $true

    if ($null -eq $expectedHeaders)
    {
        return $true
    }

    foreach ($header in $expectedHeaders)
    {
        # check if first record has a property named $header
        if ($importedCsv[0].psobject.properties.match($header).Count -eq 0)
        {
            Write-Warning "CSV is missing a header called $header."
            $hasExpectedHeaders = $false
        }
    }
    
    if (-not($hasExpectedHeaders))
    {
        Write-Host "Please add the missing headers and try again." -ForegroundColor $warningColor
    }

    return $hasExpectedHeaders
}

function Parse-AgentRecords($agentRecords)
{
    foreach ($agent in $agentRecords)
    {
        $agent.Groups = Parse-StringWithDelimiter -String $agent.Groups -Delimiter ','
        $agent.Roles = Parse-StringWithDelimiter -String $agent.Roles -Delimiter ','
    }

    return $agentRecords
}

function Parse-StringWithDelimiter($string, $delimiter)
{
    return ($string.Split("$delimiter")).Trim()
}


function Validate-AgentData($agentRecords, $allTicketScopeIds, $allGroupIds, $allRoleIds)
{
    $valid = $true
    foreach ($agent in $agentRecords)
    {
        $isNameValid = Validate-Name $agent
        $isEmailValid = Validate-Email $agent.Email
        $isLicenseValid = Validate-License $agent
        $isTicketScopeValid = Validate-TicketScope -Agent $agent -AllTicketScopeIds $allTicketScopeIds
        $areGroupsValid = Validate-Groups -Agent $agent -AllGroupIds $allGroupIds
        $areRolesValid = Validate-Roles -Agent $agent -AllRoleIds $allRoleIds

        if 
        (
            -not($isNameValid) -or
            -not($isEmailValid) -or
            -not($isLicenseValid) -or
            -not($isTicketScopeValid) -or
            -not($areGroupsValid) -or
            -not($areRolesValid)
        )
        {
            $valid = $false
        }
    }

    if (-not($valid))
    {
        Write-Host "Please correct errors in CSV and try again." -ForegroundColor $warningColor
    }

    return $valid
}

function Validate-Name($agent)
{
    $valid = ($agent."Full Name" -imatch '^\s*.+\s.+\s*$') # regex ensures a first and last name
    if (-not($valid))
    {
        Write-Warning "Name of $($agent."Full Name") is invalid for agent $($agent.Email)). Please include a first and last name using word characters."
    }
    return $valid
}

function Validate-Email($email)
{
    $valid = ($email -imatch '^\s*[+\w\.-]+@[+\w\.-]+\.\w{2,}\s*$') # regex matches an email address but allows spaces
    if (-not($valid))
    {
        Write-Warning "Email of $($agent.Email) is invalid. Please use a valid email address."
    }
    return $valid
}

function Validate-License($agent)
{
    $valid = ($agent.License -imatch '^\s*Occasional\s*$') -or ($agent.License -imatch '^\s*Full Time\s*$')
    if (-not($valid))
    {
        Write-Warning "License of $($agent.License) is invalid for agent $($agent.Email). Please use `"Full Time`" or `"Occasional`""
    }
    return $valid
}

function Validate-TicketScope($agent, $allTicketScopeIds)
{
    $valid = $allTicketScopeIds.Contains($agent.Scope.Trim())
    if (-not($valid))
    {
        Write-Warning "Scope of $($agent.Scope) is invalid for agent $($agent.Email). Please use `"Global`", `"Group`", or `"Restricted`""
    }
    return $valid
}

function Validate-Groups($agent, $allGroupIds)
{
    $valid = $true
    $hasShownValidGroups = $false
    foreach ($group in $agent.Groups)
    {
        if ($group -eq "") { continue } # allow groups to be blank

        $isValidGroup = $allGroupIds.Contains($group.Trim())
        if (-not($isValidGroup))
        {
            $valid = $false

            Write-Warning "Group of $group is invalid for agent $($agent.Email). Please use an existing group."

            if (-not($hasShownValidGroups))
            {
                Write-Host "Valid groups are:" -ForegroundColor $infoColor
                $allGroupIds.Keys | Sort-Object | Format-List | Out-String | Write-Host -ForegroundColor $infoColor
                $hasShownValidGroups = $true
            }
        }
    }

    return $valid
}

function Validate-Roles($agent, $allRoleIds)
{
    $valid = $true
    $hasShownValidRoles = $false
    foreach ($role in $agent.Roles)
    {
        if ($role -eq "") { continue } # allow roles to be blank

        $isValidRole = $allRoleIds.Contains($role.Trim())
        if (-not($isValidRole))
        {
            $valid = $false

            Write-Warning "Role of $role is invalid for agent $($agent.Email). Please use an existing role."

            if (-not($hasShownValidRoles))
            {
                Write-Host "Valid roles are:" -ForegroundColor $infoColor
                $allRoleIds.Keys | Sort-Object | Format-List | Out-String | Write-Host -ForegroundColor $infoColor
                $hasShownValidRoles = $true
            }
        }
    }

    return $valid
}

function Add-ImportedAgentsToFd($agentRecords, $url, $encodedKey, $allTicketScopeIds, $allGroupIds, $allRoleIds)
{
    $totalAdded = 0
    foreach ($agent in $agentRecords)
    {
        Write-Progress -Activity "Adding agents to FreshDesk..." -Status "$totalAdded agents added"
        $response = Add-AgentToFd $agent $url $encodedKey $allTicketScopeIds $allGroupIds $allRoleIds
        if ($response.StatusCode -eq 201)
        {
            $totalAdded++
        }
    }

    Write-Host "There were $totalAdded agents added!" -ForegroundColor $successColor
}

function Add-AgentToFd($agent, $url, $encodedKey, $allTicketScopeIds, $allGroupIds, $allRoleIds)
{
    $url = "$url/api/v2/agents"
    $headers = @{
        Authorization  = "Basic $encodedKey"
        "Content-Type" = "application/json"
    }

    $body = @{
       name = ($agent."Full Name").Trim()
       email = ($agent.Email).Trim()
       occasional   = ($agent.License -imatch '^\s*Occasional\s*$') # regex matches "Occasional" but allows spaces
       ticket_scope = $allTicketScopeIds[$agent.Scope.Trim()]
       group_ids = Get-AgentsGroupIds -Agent $agent -AllGroupIds $allGroupIds
       role_ids = Get-AgentsRoleIds -Agent $agent -AllRoleIds $allRoleIds
    } | ConvertTo-Json
    
    try
    {
        $response = Invoke-WebRequest -Method "Post" -Uri $url -Headers $headers -Body $body -ErrorVariable responseError
    }
    catch
    {
        Write-Warning "There was an error adding agent: $($agent.Email)."
        Write-Host "    $($responseError[0].Message)" -ForegroundColor $warningColor

        switch ([int]$_.Exception.Response.StatusCode)
        {
            401
            {
                # It says the API key is valid because it should have already been tested earlier in the script.
                Write-Host "    Your API key is valid, but you are not authorized to create agents." -ForegroundColor $failColor
                exit
            }
            409
            {
                Write-Host "    This error may indicate the agent already exists in FreshDesk as an agent, contact, or deleted contact." -ForegroundColor $warningColor
            }
        }
    }
    return $response
}

function Get-AgentsGroupIds($agent, $allGroupIds)
{
    if ($agent.Groups -eq "") { return ,@() }
    
    $groupIds = New-Object -TypeName System.Collections.Generic.List[UInt64]

    foreach ($group in $agent.Groups)
    {
        $groupIds.Add($allGroupIds[$group])
    }

    return Write-Output $groupIds.ToArray() -NoEnumerate
}

function Get-AgentsRoleIds($agent, $allRoleIds)
{
    if ($agent.Roles -eq "") { return ,@() }

    $roleIds = New-Object -TypeName System.Collections.Generic.List[UInt64]
    
    foreach ($role in $agent.Roles)
    {
        $roleIds.Add($allRoleIds[$role])
    }

    return Write-Output $roleIds.ToArray() -NoEnumerate
}

# This line resolves a quirk in Powershell 5 that sometimes causes arrays to get wrapped in a PSObject, causing an issue with ConvertTo-Json.
Remove-TypeData System.Array -ErrorAction SilentlyContinue

# main
Initialize-ColorScheme
Show-Introduction
Show-Tutorial
$connectionInfo = Get-ConnectionInfo
$baseUrl = $connectionInfo.BaseUrl
$encodedKey = $connectionInfo.EncodedKey
$expectedHeaders = Get-ExpectedHeaders
$allTicketScopeIds = Get-AllTicketScopeIds
$allGroupIds = Get-AllGroupIds $baseUrl $encodedKey
$allRoleIds = Get-AllRoleIds $baseUrl $encodedKey
$agentRecords = Import-AgentData $expectedHeaders $allTicketScopeIds $allGroupIds $allRoleIds
Read-Host "Press Enter to add agents to FreshDesk"
Add-ImportedAgentsToFd $agentRecords $baseUrl $encodedKey $allTicketScopeIds $allGroupIds $allRoleIds
Read-Host "Press Enter to exit"