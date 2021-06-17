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
    PS C:\>$AttackData 
.Notes 
LastModified: 6/17/2021
Author:       Travis Anderson 
              Matthew Kress-Weitenhagen
#>
Param(
    #Uri of Attach Website -Uri https://attack.mitre.org/groups/G0016/)
    [Parameter(Mandatory=$True)]
    [uri]
    $Uri
)               

#$WebRequest = (Invoke-WebRequest -Uri https://attack.mitre.org/groups/G0016/)


## Extract the tables out of the web request
$tables = @($WebRequest.ParsedHtml.getElementsByTagName("TABLE"))
$tables = ($tables | where innertext -Match DomainIDNameUse).InnerText -split "`n"


## Go through all of the rows in the table
$Return = New-Object 'System.Collections.Generic.List[System.Object]'

foreach($line in $tables)
    {
        $lineObject = New-Object PSCustomObject 
        #Regex for each type of Domain
        [regex]$DomainwithSub = "^(?<Domain>\w+)\s(?<ID>\w+\s+.\d\d\d)\s(?<Name>\w+.*)"
        [regex]$DomainNoSub = "^(?<Domain>\w+)\s(?<ID>\w+)\s(?<Name>\w+.*)"
        [regex]$JustSubID = "^(?<SubID>.\d\d\d+)\s(?<Name>\w+.*)"
        
        switch -regex ($line.Trim()) 
        {
            $DomainwithSub
            {
                $lineObject | Add-Member -MemberType NoteProperty -Name Domain -Value $Matches.Domain
                $lineObject | Add-Member -MemberType NoteProperty -Name ID -Value $Matches.ID 
                $lineObject | Add-Member -MemberType NoteProperty -Name Name -Value $Matches.Name
            }
            $DomainNoSub
            {
                $lineObject | Add-Member -MemberType NoteProperty -Name Domain -Value $Matches.Domain
                $lineObject | Add-Member -MemberType NoteProperty -Name ID -Value $Matches.ID 
                $lineObject | Add-Member -MemberType NoteProperty -Name Name -Value $Matches.Name
            }
            $JustSubID
            {
                $SubID = $Matches.SubID
                $Name = $Matches.Name
                $lineObject | Add-Member -MemberType NoteProperty -Name Domain -Value $Return[-1].Domain
                $lineObject | Add-Member -MemberType NoteProperty -Name ID -Value $(if ($Return[-1].ID -match "."){$(($Return[-1].ID -split " ")[0] + " " +  $SubID) } else {$($Return[-1].ID + " " + $SubID) })
                $lineObject | Add-Member -MemberType NoteProperty -Name Name -Value $Name
            }
            Default {  }
        }
        $Return.Add($lineObject)
    } #End Foreach
    return $Return
} #End Function