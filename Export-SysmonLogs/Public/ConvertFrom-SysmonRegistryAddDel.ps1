﻿function ConvertFrom-SysmonRegistryAddDel {
<#
.Synopsis
ConvertFrom a sysmon Registry Object Create Delete event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals:
Registry key and value create and delete operations map to this event type, which can be useful for monitoring for 
changes to Registry autostart locations, or specific malware registry modifications.


.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=12;} | select -first 1
ConvertFrom-SysmonRegistryAddDel$SysmonEvent

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
            [System.Diagnostics.Eventing.Reader.EventLogRecord[]] $Events)

 BEGIN {
    
   }
 
 PROCESS {
    Foreach ($event in $events) { 
        
        Write-Verbose ("Event type {0}" -f $Event.Id)
        if ($Event.Id -ne 12) {
            Throw ("Event is type {0} - expecting type 12 Registry Add or Delete" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
            Type = 12
            Tag = "RegistryEvent"
            Event = "Registry object added or deleted"
            EventType = $Event.Properties[0].value.tostring()
            UTCTime = $Event.Properties[1].value.tostring()
            ProcessGUID = $Event.Properties[2].value.tostring()
            ProcessId = $Event.Properties[3].value.tostring()
            Image = $Event.Properties[4].value.tostring()
            TargetObject = $Event.Properties[5].value.tostring()
        
        } | select Type,
                    Tag,
                    Event,
                    EventType,
                    UTCTime,
                    ProcessGUID,
                    ProcessId,
                    Image,
                    TargetObject
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType12 -Value ConvertFrom-SysmonRegistryAddDel -Description “ConvertFrom Sysmon Event type 12 - Registry Add or Delete”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=12;} | select -first 1
#ConvertFrom-SysmonRegistryAddDel $SysmonEvent -Verbose