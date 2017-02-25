function ConvertFrom-SysmonServiceStateChanged {
<#
.Synopsis
ConvertFrom a sysmon Service State Changed event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals Docs:
The service state change event reports the state of the Sysmon service (started or stopped).


.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=4;} | select -first 1
ConvertFrom-SysmonServiceStateChanged $SysmonEvent

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
        if ($Event.Id -ne 4) {
            Throw ("Event is type {0} - expecting type 4 Service State Changed event" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
        	Type = 4
            Tag = ""
            Event = "Sysmon service state change"
            UTCTime = $Event.Properties[0].value.tostring()
            State = $Event.Properties[1].value.tostring()
            Version = $Event.Properties[2].value.tostring()
            SigSchemaVersion = $Event.Properties[3].value.tostring()
        } | select Type,
                Tag,
                Event,
                UTCTime,
                State,
                Version,
                SigSchemaVersion
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType4 -Value ConvertFrom-SysmonServiceStateChanged -Description “ConvertFrom Sysmon Event type 4 - Sysmon Service State Changed”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=4;} | select -first 1
#ConvertFrom-SysmonServiceStateChanged $SysmonEvent -Verbose