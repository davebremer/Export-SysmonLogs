function ConvertFrom-SysmonProcessTerminate {
<#
.Synopsis
ConvertFrom a sysmon process terminated event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals Doc:
The process terminate event reports when a process terminates. It provides the UtcTime, ProcessGuid and ProcessId 
of the process.

.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=5;} | select -first 1
ConvertFrom-SysmonProcessTerminate $SysmonEvent

.LINK
https://technet.microsoft.com/en-us/sysinternals/sysmon

.NOTES
 Author: Dave Bremer
 
#>

    [cmdletBinding(DefaultParametersetName="user")]
    Param ([Parameter (
            Mandatory=$True,
            ValueFromPipelineByPropertyName = $TRUE,
            ValueFromPipeLine = $TRUE,
            Position = 0
                )]
            [ValidateNotNullOrEmpty()]
            [System.Diagnostics.Eventing.Reader.EventLogRecord] $Events)

 BEGIN {
   
   }
 
 PROCESS {
     Foreach ($event in $events) { 
           
            Write-Verbose ("Event type {0}" -f $Event.Id)
            if ($Event.Id -ne 5) {
                Throw ("Event is type {0} - expecting type 5 Process Terminate event" -f $Event.Id)
            }
            # Create Object
    

            New-Object -Type PSObject -Property @{
                Type = 5 
                Tag = "ProcessTerminate"
                Event = "Process terminated"
                UTCTime = $Event.Properties[0].value.tostring()
                ProcessGUID = $Event.Properties[1].value.tostring()
                ProcessId = $Event.Properties[2].value.tostring()
                Image = $Event.Properties[3].value.tostring()
        
            } | select Type,
                        Tag,
                        Event,
                        UTCTime,
                        ProcessGUID,
                        ProcessId,
                        Image
        }
    }
END {}

}
Set-Alias -Name ConvertFrom-SysmonType5 -Value ConvertFrom-SysmonProcessTerminate -Description “ConvertFrom Sysmon Event type 5 - Process Terminate”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=5;} | select -first 1
#ConvertFrom-SysmonProcessTerminate $SysmonEvent -Verbose