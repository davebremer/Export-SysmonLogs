
function Export-SysmonLogs {
<#
.Synopsis
 Exports sysmon logs to a number of CSV files based on event-id - directory hard-coded to "c:\temp\sysmon" right now

.DESCRIPTION
     Exports sysmon logs to a number of CSV files based on event-id. Also creates a file "frequency.csv" that gives a count of how many events were exported for each event type.

.EXAMPLE
    Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";ID=1,4,6,8,11,12,13,15,16} | Export-SysmonLogs
    Currently these get dumped in c:\temp\sysmon

.LINK

.NOTES
 Author: Dave Bremer
 TODO:
    * Add path variable to select output dir
        - Error check
        - offer to create?
    * Add option to select input path to a saved evtx file
    * Add default option that without any flags will dump everything from sysmonlogs to current directory - no need to do get-winevent
    * Add option to select date range (or everything from a date till now
    * Add option to select certain types. This could be done by manually calling the convertfrom-sysmon* functions - not sure if necessary
    * Add option to merge all csv's into an xlsx with seperate tab per sheet
        ** Optionally delete csv files after merging to csv
    * Some kind of progress would be  good

    None of this gets into actual analysis - after the file handlings sorted, I need to start thinking about what kind of analysis can be done via
    powershell rather than booting the load onto excel.

#>

    [cmdletBinding()]
    Param ([Parameter (
            Mandatory=$False,
            ValueFromPipelineByPropertyName = $False,
            ValueFromPipeLine = $False
                )]
            [String]$Path = (get-location)
            )

 BEGIN {
    

    $Freq =  @{}
    
   }
 
 PROCESS {
 
    Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";} | ForEach-Object  {
         $event = $_
         $command = ("ConvertFrom-SysmonType{0} `$Event" -f $event.ID)
         $filename = ("{0}\SysmonType{1}.csv" -f $Path,$event.ID)
         
         $freq.($event.id) +=1
         Invoke-Expression $command | export-csv $filename -NoTypeInformation -Append
    }
    
        
}

END {
$freq.GetEnumerator() |  select @{n="Type";e={$_.name}},@{n="Frequency";e={$_.value -as [int]}} | sort -Property Type
$freq.GetEnumerator() |  select @{n="Type";e={$_.name}},@{n="Frequency";e={$_.value -as [int]}} | sort -Property Type | export-csv "$Path\frequency.csv" -NoTypeInformation
}
}

#$eone = Get-WinEvent -path 'C:\Users\dbremer\Documents\sysmon logs\sysmonlogs1.evtx' | select -first 1 
#$e = Get-WinEvent -path 'C:\Users\dbremer\Documents\sysmon logs\sysmonlogs1.evtx' 
#$e | Export-SysmonLogs
#Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";ID=1,4,6,8,11,12,13,15,16} | Export-SysmonLogs