function ConvertFrom-SysmonWmiEventConsumerToFilterActivity {
<#
.Synopsis
This event logs the registration of WMI consumers, recording the consumer name, log, and destination.

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 


.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=21;} | select -first 1
ConvertFrom-SysmonFileCreateStreamHash $SysmonEvent


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
    $TypeID = 21
    
   }
 
 PROCESS {
    Foreach ($event in $events) { 

        Write-Verbose ("Event type {0}" -f $Event.Id)
        if ($Event.Id -ne $TypeID) {
            Throw ("Event is type {0} - expecting type {1} File Stream Create event" -f $Event.Id, $TypeID)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
        	Type = $TypeID
            Tag = "WmiEventConsumerToFilter"
            Event = "WmiEventConsumerToFilter activity detected"
            EventType = $Event.Properties[0].value.tostring()
            UTCTime = $Event.Properties[1].value.tostring()
            Operation = $Event.Properties[2].value.tostring()
            User = $Event.Properties[3].value.tostring()
            Consumer = $Event.Properties[4].value.tostring()
            Filter = $Event.Properties[5].value.tostring()
            
        } | select Type,
                    Tag,
                    Event,
                    EventType,
                    UTCTime,
                    Operation,
                    User,
                    Consumer,
                    Filter
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType19 -Value ConvertFrom-SysmonWmiEventFilterActivity -Description “ConvertFrom Sysmon Event type 21 - WmiEventFilter activity detected”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=21;} | select -first 1
# ConvertFrom-SysmonWmiEventFilterActivity $SysmonEvent -Verbose