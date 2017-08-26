
function Export-SysmonLogs {
<#
.Synopsis
    Exports sysmon logs to a number of CSV files based on event-id

.DESCRIPTION
    Exports sysmon logs to a number of CSV files based on event-id. 
    Also creates a file "frequency.csv" that gives a count of how many events were exported for each event type.

    CAUTION: Records are appended to any existing csv file

.PARAMETER File
    The location of a saved sysmon EVTX file

.PARAMETER Path
    The location to generate the files

.PARAMETER ID
    The ID's that you want to export - can be an array of integers. These must be valid Sysmon event IDs

.PARAMETER StartTime
    The earliest time for logs to be exported

.PARAMETER EndTime
    The latest time for logs to be exported

.PARAMETER MaxEvents
Specifies the maximum number of events that are returned. Enter an integer. The default is to return all the events in the logs or files.

.EXAMPLE
    Export-SysmonLogs
    All Sysmon events are dumped to a number of CSV files in the current directory

.EXAMPLE
    Export-SysmonLogs -path c:\temp\sysmon
    All Sysmon events are dumped c:\temp\sysmon

.EXAMPLE
    Export-SysmonLogs -path d:\sysmon -file c:\temp\sysmoncopy.evtx
    A file c:\temp\sysmoncopy.evtx is read with csv files created in d:\sysmon

.EXAMPLE
    Export-SysmonLogs -ID 2,4,6,8
    Exports only event types listed to the current directory

.LINK
    https://technet.microsoft.com/en-us/sysinternals/sysmon

.NOTES
 Author: Dave Bremer
 TODO:
    * DONE Add path variable to select output dir
        DONE - Error check
        - offer to create?
    DONE * Add option to select input path to a saved evtx file
    DONE * Add default option that without any flags will dump everything from sysmonlogs to current directory - no need to do get-winevent
    DONE * Add option to select date range (or everything from a date till now
    DONE * Add option to select certain types. This could be done by manually calling the convertfrom-sysmon* functions - not sure if necessary
    * Extract computername - don't allow Path for this. Different logset
    * Add option to merge all csv's into an xlsx with seperate tab per sheet
        ** Optionally delete csv files after merging to csv
    * Some kind of progress would be  good

    None of this gets into actual analysis - after the file handlings sorted, I need to start thinking about what kind of analysis can be done via
    powershell rather than booting the load onto excel.

#>

    [cmdletBinding()]
    Param (
            [Parameter(position = 0)]
            [ValidateScript({If(Test-Path $_ -PathType Container){$true}else{Throw "Invalid output path given: $_"} })]
            [String]$Path = (get-location),
            
            [validateset(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,255)]
            [int[]]$ID,

            [Parameter()]
            [ValidateScript({If(Test-Path $_ -PathType Leaf){$true}else{Throw "Invalid EVTX file given: $_"} })]
            [string]$File,
            
            [Parameter()]
            [string]$StartTime,

            [Parameter()]
            [string]$EndTime,

            [Parameter()]
            [ValidateRange(1, [int]::MaxValue)]
            [int64]$MaxEvents

           )


 BEGIN {
    

    $Freq =  @{}
    
   }
 
 PROCESS {
 
    if ($file) {
        $HashTable = @{path=$File}
    } else {
        $HashTable = @{logname="Microsoft-Windows-Sysmon/Operational"}
    }

    if ($id) {
        $HashTable.Add("ID", $id)
    }

    if ($StartTime) {
        $HashTable.Add("StartTime", $StartTime)
    }

    if ($EndTime) {
        $HashTable.Add("EndTime", $EndTime)
    }

    

    write-verbose ("FilterHashtable:`n{0}`n`n" -f $($HashTable| Out-String))

    $getwineventParams = @{FilterHashtable = $HashTable}

    if ($MaxEvents) {
        $getwineventParams.Add("MaxEvents", $MaxEvents)
    }

    write-verbose ("WinEvent Hashtable:`n{0}`n`n" -f $($getwineventParams| Out-String))

    Get-WinEvent @getwineventParams | ForEach-Object  {
         $event = $_
         $command = ("ConvertFrom-SysmonType{0} `$Event" -f $event.ID)
         $filename = ("{0}\SysmonType{1}.csv" -f $Path,$event.ID)
         
         $freq.($event.id) +=1
         Invoke-Expression $command | export-csv $filename -NoTypeInformation -Append
    }
    
        
}

END {
    #Write the frequency of each type to screen
    $freq.GetEnumerator() |
        select @{n="Type";e={$_.name}},@{n="Frequency";e={$_.value -as [int]}} | 
        sort -Property Type

    #Make a frequency file
    $freq.GetEnumerator() |  
        select @{n="Type";e={$_.name}},@{n="Frequency";e={$_.value -as [int]}} | 
        sort -Property Type | 
        export-csv "$Path\frequency.csv" -NoTypeInformation
}
}

