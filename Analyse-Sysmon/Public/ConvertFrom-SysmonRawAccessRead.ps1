function ConvertFrom-SysmonRawAccessRead {
<#
.Synopsis
ConvertFrom a sysmon Raw Access Read event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals Documentation:
The RawAccessRead event detects when a process conducts reading operations from the drive using the \\.\ denotation. 
This technique is often used by malware for data exfiltration of files that are locked for reading, as well as to 
avoid file access auditing tools. The event indicates the source process and target device.

.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=9;} | select -first 1
ConvertFrom-SysmonRawAccessRead $SysmonEvent

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
        
        Write-Verbose ("Event type {0}" -f $Event.Id)
        if ($Event.Id -ne 9) {
            Throw ("Event is type {0} - expecting type 9 Raw Access Read event" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
        	Type = 9
            Tag = "RawAccessRead"
            Event = "RawAccessRead detected"
            UTCTime = $Event.Properties[0].value.tostring()
            ProcessGUID = $Event.Properties[1].value.tostring()
            ProcessID = $Event.Properties[2].value.tostring()
            Image = $Event.Properties[3].value.tostring()
            Device = $Event.Properties[4].value.tostring()
           
        } | select Type,
                    Tag,
                    Event,
                    UTCTime,
                    ProcessGUID,
                    ProcessId,
                    Image,
                    Device
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType9 -Value ConvertFrom-SysmonRawAccessRead -Description “ConvertFrom Sysmon Event type 9 Raw Access Read”
#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=9;} | select -first 1
#ConvertFrom-SysmonRawAccessRead $SysmonEvent -Verbose