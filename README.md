# Add-FreshDeskAgents

## Objective
- Import new agents into FreshDesk with a CSV file.

## Procedure
1. Fill out a CSV with the following headers:
    - Full Name
    - Email
    - License
      - Accepts "Full Time" or "Occasional".
    - Scope
      - Accepts "Global", "Group", or "Restricted".
    - Group
      - Accepts one or more existing groups, comma separated. May also be left empty.
    - Roles
      - Accepts one or more existing roles, comma separated. May also be left empty.
2. Set your [execution policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-executionpolicy) to allow the script to run.
3. Run the script and follow the prompts.
