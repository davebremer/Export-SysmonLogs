function ConvertFrom-SysmonRegistryRename {
<#
.Synopsis
    ConvertFrom a sysmon Registry Rename event, returning an object with data

.DESCRIPTION
    This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

    From Sysinternals:
        Registry key and value rename operations map to this event type, 
        recording the new name of the key or value that was renamed.


.EXAMPLE
    $SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=14;} | select -first 1
    ConvertFrom-SysmonRegistryRename $SysmonEvent

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
        if ($Event.Id -ne 14) {
            Throw ("Event is type {0} - expecting type 14 Registry Rename" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
            Type = 14
            Tag = "RegistryEvent"
            Event = "Registry value (Key and Value) Rename"
            EventType = $Event.Properties[0].value.tostring()
            UTCTime = $Event.Properties[1].value.tostring()
            ProcessGuid = $Event.Properties[2].value.tostring()
            ProcessId = $Event.Properties[3].value.tostring()
            Image = $Event.Properties[4].value.tostring()
            TargetObject = $Event.Properties[5].value.tostring()
            NewName = $Event.Properties[6].value.tostring()
            
        } | select Type,
                    Tag,
                    Event,
                    EventType,
                    UTCTime,
                    ProcessGuid,
                    ProcessId,
                    Image,
                    TargetObject,
                    NewName
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType14 -Value ConvertFrom-SysmonRegistryRename -Description “ConvertFrom Sysmon Event type 14 - Registry Rename”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=14;} | select -first 1
#ConvertFrom-SysmonRegistryRename $SysmonEvent -Verbose