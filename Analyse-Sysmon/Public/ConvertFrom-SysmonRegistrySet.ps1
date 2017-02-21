function ConvertFrom-SysmonRegistrySet {
<#
.Synopsis
ConvertFrom a sysmon process create event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals:
This Registry event type identifies Registry value modifications. The event records the value written for Registry values of type DWORD and QWORD.


.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=13;} | select -first 1
ConvertFrom-SysmonRegistrySet $SysmonEvent

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
            [System.Diagnostics.Eventing.Reader.EventLogRecord[]] $Events)

 BEGIN {
    
   }
 
 PROCESS {
    Foreach ($event in $events) { 
        $eventXML = [xml]$Event.ToXml()
        Write-Verbose ("Event type {0}" -f $Event.Id)
        if ($Event.Id -ne 13) {
            Throw ("Event is type {0} - expecting type 13 Process Create event" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
            Type = 13
            Tag = "RegistryEvent"
            Event = "Registry value set"
            EventType = $Event.Properties[0].value.tostring()
            UTCTime = $Event.Properties[1].value.tostring()
            ProcessGuid = $Event.Properties[2].value.tostring()
            ProcessId = $Event.Properties[3].value.tostring()
            Image = $Event.Properties[4].value.tostring()
            TargetObject = $Event.Properties[5].value.tostring()
            Details = $Event.Properties[6].value.tostring()
            
        }
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType13 -Value ConvertFrom-SysmonRegistrySet -Description “ConvertFrom Sysmon Event type 1 - Process Create”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=13;} | select -first 1
#ConvertFrom-SysmonRegistrySet $SysmonEvent -Verbose