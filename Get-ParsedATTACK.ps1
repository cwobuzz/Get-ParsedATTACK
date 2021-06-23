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

$WebRequest = Invoke-WebRequest -Uri $Uri
## Extract the tables out of the web request
$tables = @($WebRequest.ParsedHtml.getElementsByTagName("TABLE"))
$tables = ($tables | where innertext -Match DomainIDNameUse).InnerText -split "`n"


## Go through all of the rows in the table
$return = $null
 $return = foreach($line in $tables)
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
                 [PSCustomObject]@{
                    Domain = $Matches.Domain
                    ID = $Matches.SubID
                    Name = $Matches.Name
                        }
            }
            Default {  }
        }

    } #End Foreach
    # Counter
    $counter = 0

    #New foreach cannot figure out how to use PSCustomObject[-1]
    foreach ($obj in $Return) {
        if ($obj.Domain -eq $null ) {
            $obj.Domain = $Return[$counter - 1].Domain
            if ($obj.ID -match "^\.") {
                $obj.ID = $($Return[$counter -1 ].ID).split(" ")[0] + " " + $obj.ID}
            $counter ++

        }
        else {
            #continue
            $counter ++
        }
        
    } # End Foreach
$return
} #End Function

