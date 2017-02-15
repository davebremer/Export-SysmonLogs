function ConvertFrom-SysmonProcessTerminate {
<#
.Synopsis
ConvertFrom a sysmon process terminated event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals Doc:
The process terminate event reports when a process terminates. It provides the UtcTime, ProcessGuid and ProcessId of the process.


.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=1;} | select -first 1
ConvertFrom-SysmonProcessTerminate $SysmonEvent

.LINK
https://technet.microsoft.com/en-us/sysinternals/sysmon

.NOTES
 Author: Dave Bremer
 Hat-Tip: https://infracloud.wordpress.com/2016/05/12/read-sysmon-logs-from-powershell/
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
            $eventXML = [xml]$Event.ToXml()
            Write-Verbose ("Event type {0}" -f $Event.Id)
            if ($Event.Id -ne 5) {
                Throw ("Event is type {0} - expecting type 5 Process Terminate event" -f $Event.Id)
            }
            # Create Object
    

            New-Object -Type PSObject -Property @{
                UTCTime = $eventXML.Event.EventData.Data[0].'#text'
                ProcessId = $eventXML.Event.EventData.Data[2].'#text'
                Image = $eventXML.Event.EventData.Data[3].'#text'
        
            }
        }
    }
END {}

}
Set-Alias -Name ConvertFrom-SysmonType5 -Value ConvertFrom-SysmonProcessTerminate -Description “ConvertFrom Sysmon Event type 5 - Process Terminate”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=5;} | select -first 1
#ConvertFrom-SysmonProcessTerminate $SysmonEvent -Verbose