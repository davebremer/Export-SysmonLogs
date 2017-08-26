function ConvertFrom-SysmonServicePipeConnected {
<#
.Synopsis
ConvertFrom a sysmon Service Pipe Connected loaded event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals Docs:



.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=18;} | select -first 1
ConvertFrom-SysmonServicePipeConnected $SysmonEvent

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
        if ($Event.Id -ne 18) {
            Throw ("Event is type {0} - expecting type 18 Named pipe connected" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
        	Type = 18
            Tag = "PipeEvent"
            Event = "Named pipe connected"
            UTCTime = $Event.Properties[0].value.tostring()
            ProcessGUID = $Event.Properties[1].value.tostring()
            ProcessID = $Event.Properties[2].value.tostring()
            PipeName = $Event.Properties[3].value.tostring()
            Image = $Event.Properties[4].value.tostring()
        } | select Type,
                Tag,
                Event,
                UTCTime,
                ProcessGUID,
                ProcessID,
                PipeName,
                Image
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType18 -Value ConvertFrom-SysmonServicePipeConnected -Description “ConvertFrom Sysmon Event type 18 - Sysmon Named pipe connected”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=18;} | select -first 1
#ConvertFrom-SysmonServicePipeConnected $SysmonEvent -Verbose