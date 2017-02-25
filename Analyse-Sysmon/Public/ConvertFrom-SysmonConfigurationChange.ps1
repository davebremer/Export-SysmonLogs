function ConvertFrom-SysmonConfigurationChange {
<#
.Synopsis
ConvertFrom a sysmon Configuration change event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals Docs:
Sysmon configuration change (cannot be filtered)


.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=16;} | select -first 1
ConvertFrom-SysmonConfigurationChanged $SysmonEvent

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
        if ($Event.Id -ne 16) {
            Throw ("Event is type {0} - expecting type 16 sysmon Configuration Change event" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
        	Type = 16
            Tag = ""
            Event = "Sysmon configuration change"
            UTCTime = $Event.Properties[0].value.tostring()
            Configuration = $Event.Properties[1].value.tostring()
            ConfigurationFileHash = $Event.Properties[2].value.tostring()
        } | select Type,
                    Tag,
                    Event,
                    UTCTime,
                    Configuration,
                    ConfigurationFileHash
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType16 -Value ConvertFrom-SysmonConfigurationChange -Description “ConvertFrom Sysmon Event type 16 - Sysmon Service Configuration Changed”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=16;} | select -first 1
#ConvertFrom-SysmonConfigurationChanged $SysmonEvent -Verbose