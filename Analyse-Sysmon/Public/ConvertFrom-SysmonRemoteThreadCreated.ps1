function ConvertFrom-SysmonRemoteThreadCreated {
<#
.Synopsis
ConvertFrom a sysmon driver loaded event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals Docs:
The service state change event reports the state of the Sysmon service (started or stopped).


.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=8;} | select -first 1
ConvertFrom-SysmonRemoteThreadCreated $SysmonEvent

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
        if ($Event.Id -ne 8) {
            Throw ("Event is type {0} - expecting type 8 Driver Loaded event" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
        	Type = 8
            Tag = "CreateRemoteThread"
            Event = "CreateRemoteThread detected"
            UTCTime = $Event.Properties[0].value.tostring()
            SourceProcessGuid = $Event.Properties[1].value.tostring()
            SourceProcessId = $Event.Properties[2].value.tostring()
            SourceImage = $Event.Properties[3].value.tostring()
            TargetProcessGuid = $Event.Properties[4].value.tostring()
            TargetProcessId = $Event.Properties[5].value.tostring()
            TargetImage = $Event.Properties[6].value.tostring()
            NewThreadId = $Event.Properties[7].value.tostring()
            StartAddress = $Event.Properties[8].value.tostring()
            StartModule = $Event.Properties[9].value.tostring()
            StartFunction= $Event.Properties[10].value.tostring()
        } | select Type,
                    Tag,
                    Event,
                    UTCTime,
                    SourceProcessGuid,
                    SourceProcessId,
                    SourceImage,
                    TargetProcessGuid,
                    TargetProcessId,
                    TargetImage,
                    NewThreadId,
                    StartAddress,
                    StartModule,
                    StartFunction
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType8 -Value ConvertFrom-SysmonRemoteThreadCreated -Description “ConvertFrom Sysmon Event type 8 - Sysmon Service State Changed”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=8;} | select -first 1
#ConvertFrom-SysmonRemoteThreadCreated $SysmonEvent -Verbose