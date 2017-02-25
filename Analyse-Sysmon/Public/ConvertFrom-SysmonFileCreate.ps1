function ConvertFrom-SysmonFileCreate {
<#
.Synopsis
ConvertFrom a sysmon file create event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals:
File create operations are logged when a file is created or overwritten. This event is useful for monitoring autostart 
locations, like the Startup folder, as well as temporary and download directories, which are common places malware drops 
during initial infection.


.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=11;} | select -first 1
ConvertFrom-SysmonFileCreate $SysmonEvent

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

        Write-Verbose ("Event type {0}" -f $Event.Id)
        if ($Event.Id -ne 11) {
            Throw ("Event is type {0} - expecting type 11 File Create event" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
        	Type = 11
            Tag = "FileCreate"
            Event = "File created"
            UTCTime = $Event.Properties[0].value.tostring()
            ProcessGUID = $Event.Properties[1].value.tostring()
            ProcessId = $Event.Properties[2].value.tostring()
            Image = $Event.Properties[3].value.tostring()
            TargetFilename = $Event.Properties[4].value.tostring()
            CreationUtcTime = $Event.Properties[5].value.tostring()
            
        } | select Type,
                    Tag,
                    Event,
                    UTCTime,
                    ProcessGUID,
                    ProcessId,
                    Image,
                    TargetFilename,
                    CreationUtcTime
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType11 -Value ConvertFrom-SysmonFileCreate -Description “ConvertFrom Sysmon Event type 11 - File Create”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=11;} | select -first 1
#ConvertFrom-SysmonFileCreate $SysmonEvent -Verbose