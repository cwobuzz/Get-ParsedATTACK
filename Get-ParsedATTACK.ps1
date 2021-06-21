Function Get-ParsedATTACK
{ 
<# 
.SYNOPSIS 
    This function will Parse the data from Mitre Attacks web page. 
 
.DESCRIPTION 
     This function gets Domain, Attack ID, sub attack and Name from the web page.
 
.PARAMETER  
    Uri must be one the APT Groups
 
.EXAMPLE 
    PS C:\>$AttackData = Get-ParsedATTACK -Uri https://attack.mitre.org/groups/G0016/
    PS C:\>$AttackData  | Export-Csv -NoTypeInformation -Delimiter "`t" -Path C:\Users\User\Desktop\TabbedAttack.csv
.Notes 
LastModified: 6/21/2021
Author:       Travis Anderson 
              Matthew Kress-Weitenhagen
#>
Param(
    #Uri of Attach Website -Uri https://attack.mitre.org/groups/G0016/)
    [Parameter(Mandatory=$True)]
    [uri]
    $Uri
)               

## Extract the tables out of the web request
$tables = @($WebRequest.ParsedHtml.getElementsByTagName("TABLE"))
$tables = ($tables | where innertext -Match DomainIDNameUse).InnerText -split "`n"


## Go through all of the rows in the table
$Return = New-Object 'System.Collections.Generic.List[System.Object]'

foreach($line in $tables)
    {

        #Regex for each type of Domain
        [regex]$DomainwithSub = "^(?<Domain>\w+)\s(?<ID>\w+\s+.\d\d\d)\s(?<Name>\w+.*)"
        [regex]$DomainNoSub = "^(?<Domain>\w+)\s(?<ID>\w+)\s(?<Name>\w+.*)"
        [regex]$JustSubID = "^(?<SubID>.\d\d\d+)\s(?<Name>\w+.*)"
        
        switch -regex ($line.Trim()) 
        {
            $DomainwithSub
            {
                [PSCustomObject]@{
                    Domain = $Matches.Domain
                    ID = $Matches.ID
                    Name = $Matches.Name
                        } 
            }
            $DomainNoSub
            {
                [PSCustomObject]@{
                    Domain = $Matches.Domain
                    ID = $Matches.ID
                    Name = $Matches.Name
                        }
            }
            $JustSubID
            {
                $SubID = $Matches.SubID
                $Name = $Matches.Name
                 [PSCustomObject]@{
                    Domain = $Return[-1].Domain
                    ID = $(if ($Return[-1].ID -match "."){$(($Return[-1].ID -split " ")[0] + " " +  $SubID) } else {$($Return[-1].ID + " " + $SubID) })
                    Name = $Name
                        }
            }
            Default {  }
        }

    } #End Foreach

} #End Function

