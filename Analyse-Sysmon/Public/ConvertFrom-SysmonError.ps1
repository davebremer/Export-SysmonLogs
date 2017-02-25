function ConvertFrom-SysmonError {
<#
.Synopsis
ConvertFrom a sysmon Error event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 


.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=255;} | select -first 1
ConvertFrom-SysmonError $SysmonEvent

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
        if ($Event.Id -ne 255) {
            Throw ("Event is type {0} - expecting type 255 Error event" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
        	Type = 255
            Tag = ""
            Event = "Error report"
            UTCTime = $Event.Properties[0].value.tostring()
            ID = $Event.Properties[1].value.tostring()
            Description = $Event.Properties[2].value.tostring()
            
        } | select Type,
                Tag,
                Event,
                UTCTime,
                ID,
                Description
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType255 -Value ConvertFrom-SysmonError -Description “ConvertFrom Sysmon Event type 255 - Sysmon Error Report”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=255;} | select -first 1
#ConvertFrom-SysmonError $SysmonEvent -Verbose