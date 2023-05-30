<#
- Problem statement
    - When adding a large list of new agents into FreshDesk, such as when bringing in a whole department, it takes a long time, as they must be entered one by one.
- Use cases and features
    - Enter spreadsheet with users and their appropriate group > creates all of them in FreshDesk, assigns license, group, scope, etc.
    - Implements Write-Progress
- Minimum viable product
- Inputs
    - CSV file
- Outputs
    - List of agents created successfully and unsuccessfully
    - Can it return a link to each agent profile?
- Program flow
- Functions
- Classes and namespaces
- Input validation
    - Does it need to verify that the appropriate number of licenses are available?
    - Agent doesn't already exist in the system
    - Invalid API key
    - API key lacking permissions
    - License, ticket scope, group Ids, or Role Ids case insensitive
    - Entered duplicate agents on spreadsheet
    - Certain fields on spreadsheet should be allowed to be empty
    - Ticket scope or email must not be empty
    - Don't allow name to be empty
- Output validation
    - Agent was created with all the right properties
- Done but not tested
    - Validating for first and last name
    - Validating email address
    - Validating role exists
    - Validating group exists
- Done and tested
    - Parsing delimited strings
    - CSV has correct headers
    - CSV is actually a CSV file
    - CSV has content
- Known issues
    - When outputting valid groups or roles, it's not in a freindly list format.
#>

# functions
function Initialize-ColorScheme
{
    $script:successColor = "Green"
    $script:infoColor = "DarkCyan"
    $script:failColor = "Red"
    # warning color is yellow, but that is built into Write-Warning
}

function Show-Introduction
{
    Write-Host "This script takes a CSV file with users and adds them into FreshDesk as agents." -ForegroundColor $infoColor
    Read-Host "Press Enter to continue"
}

function Show-Tutorial
{
    Write-Host ("Please fill out a CSV with the following headers: `n" +
        "Full Name `n" +
        "Email `n" +
        "License `n" +
        "`t Accepts `"Full Time`" or `"Occasional`" `n" +
        "Scope `n" +
        "`t Accepts `"Global`", `"Group`", or `"Restricted`" `n" +
        "Groups `n" +
        "`t Accepts one or more existing groups, comma separated. `n" +
        "Roles `n" +
        "`t Accepts one or more existing roles, comma separated. `n") -ForegroundColor $infoColor
}

function Get-ExpectedHeaders
{
    return @("Full Name", "Email", "License", "Scope", "Groups", "Roles")
}

function Prompt-Csv($expectedHeaders)
{
    do
    {
        $path = Read-Host "Enter path to CSV"
        $path = $path.Trim('"')

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


function Prompt-ApiKey
{
    $secureString = Read-Host "Please enter your API key" -AsSecureString
    $plainKey = Convert-SecureStringToPlainText $secureString
    return ConvertTo-Base64 ($plainKey + ":X")
}
function Convert-SecureStringToPlainText($secureString)
{
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString)
    return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
}

function ConvertTo-Base64($plainText)
{
    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($plainText))
}

function Get-AllTicketScopeIds
{
    return @{
        Global     = 1
        Group      = 2
        Restricted = 3
    }
}

function Get-AllGroupIds($encodedKey)
{
    $url = "https://blueravensolar.freshdesk.com/api/v2/groups"
    $headers = @{
        Authorization = "Basic $encodedKey"      
    }

    SafelyInvoke-RestMethod -Method "Get" -Url $url -Headers $headers
    $lookupTable = @{}
    foreach ($group in $groups)
    {
        $lookupTable.Add($group.name, $group.id)
    }

    return $lookupTable
}

function SafelyInvoke-RestMethod($uri, $method, $headers, $body)
{
    try
    {
        $response = Invoke-RestMethod -Uri $uri -Method $method -Headers $headers -Body $body -ErrorVariable "responseError"
    }
    catch
    {
        # Write-Host $responseError -ForegroundColor $failColor
        # exit
        Throw $responseError # go back to exiting when done testing
    }

    return $response
}

function Get-AllRoleIds($encodedKey)
{
    $url = "https://blueravensolar.freshdesk.com/api/v2/roles"
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
        Write-Host "Please correct errors in CSV and try again." -ForegroundColor $failColor
    }

    return $valid
}

function Validate-Name($agent)
{
    return ($agent."Full Name" -imatch '^\s*\w+\s\w+\s*$') # regex ensures a first and last name
}

function Validate-Email($email)
{
    return ($email -imatch '^\s*[+\w\.-]+@[+\w\.-]+\.\w{2,}\s*$') # regex matches an email address but allows spaces
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
        $isValidGroup = $allGroupIds.Contains($group.Trim())
        if (-not($isValidGroup))
        {
            $valid = $false

            Write-Warning "Group of $group is invalid for agent $($agent.Email). Please use an existing group."

            if (-not($hasShownValidGroups))
            {
                Write-Host "Valid groups are:" -ForegroundColor $infoColor
                Write-Host $allGroupIds.Keys -ForegroundColor $infoColor
                $hasShownValidGroups = $true
            }
        }
    }
    # should also return true when agent.Groups is empty
    return $valid
}

function Validate-Roles($agent, $allRoleIds)
{
    $valid = $true
    $hasShownValidRoles = $false
    foreach ($role in $agent.Roles)
    {
        $isValidRole = $allRoleIds.Contains($role.Trim())
        if (-not($isValidRole))
        {
            $valid = $false

            Write-Warning "Role of $role is invalid for agent $($agent.Email). Please use an existing role."

            if (-not($hasShownValidRoles))
            {
                Write-Host "Valid roles are:" -ForegroundColor $infoColor
                Write-Host $allRoleIds.Keys -ForegroundColor $infoColor
                $hasShownValidRoles = $true
            }
        }
    }

    # should also return true when agent.Roles is empty
    return $valid
}

function Add-ImportedAgentsToFd($agentRecords, $encodedKey, $allTicketScopeIds, $allGroupIds, $allRoleIds)
{
    foreach ($agent in $agentRecords)
    {
        Add-AgentToFd $agent $encodedKey $allTicketScopeIds $allGroupIds $allRoleIds
    }
}

function Add-AgentToFd($agent, $encodedKey, $allTicketScopeIds, $allGroupIds, $allRoleIds)
{
    $url = "https://blueravensolar.freshdesk.com/api/v2/agents"
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

    SafelyInvoke-RestMethod -Method "Post" -Uri $url -Headers $headers -Body $body
}


function Get-AgentsGroupIds($agent, $allGroupIds)
{
    $groupIds = New-Object -TypeName System.Collections.Generic.List[string]

    foreach ($group in $agent.Groups)
    {
        $groupIds.Add($allGroupIds[$group])
    }

    return $groupIds.ToArray()
}

function Get-AgentsRoleIds($agent, $allRoleIds)
{
    $roleIds = New-Object -TypeName System.Collections.Generic.List[string]
    
    foreach ($role in $agent.Roles)
    {
        $roleIds.Add($allRoleIds[$role])
    }

    return $roleIds.ToArray()
}

# main
Initialize-ColorScheme
Show-Introduction
Show-Tutorial
$expectedHeaders = Get-ExpectedHeaders
do
{
    $agentRecords = Prompt-Csv $expectedHeaders
    $agentRecords = Parse-AgentRecords $agentRecords
    if ($null -eq $encodedKey)
    {
        $encodedKey = Prompt-ApiKey
    }    
    if ($null -eq $allTicketScopeIds)
    {
        $allTicketScopeIds = Get-AllTicketScopeIds
    }
    if ($null -eq $allGroupIds)
    {
        $allGroupIds = Get-AllGroupIds $encodedKey
    }
    if ($null -eq $allRoleIds)
    {
        $allRoleIds = Get-AllRoleIds $encodedKey
    }    
    $isValidAgentData = Validate-AgentData -AgentRecords $agentRecords -AllTicketScopeIds $allTicketScopeIds -AllGroupIds $allGroupIds -AllRoleIds $allRoleIds
}
while (-not($isValidAgentData))
Read-Host "Press Enter to add agents to FreshDesk"
Add-ImportedAgentsToFd $agentRecords $encodedKey $allTicketScopeIds $allGroupIds $allRoleIds
Read-Host "Press Enter to exit"