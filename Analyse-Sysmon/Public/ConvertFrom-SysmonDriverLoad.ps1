function ConvertFrom-SysmonDriverLoad {
<#
.Synopsis
ConvertFrom a sysmon driver loaded event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals Docs:
The driver loaded events provides information about a driver being loaded on the system. The configured hashes are provided as well as signature information. The signature is created asynchronously for performance reasons and indicates if the file was removed after loading.


.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=6;} | select -first 1
ConvertFrom-SysmonDriverLoad $SysmonEvent

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
        if ($Event.Id -ne 6) {
            Throw ("Event is type {0} - expecting type 6 Driver Loaded event" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
        	Type = 6
            Tag = "DriverLoad"
            Event = "Driver Loaded"
            UTCTime = $Event.Properties[0].value.tostring()
            ImageLoaded = $Event.Properties[1].value.tostring()
            Hashes = $Event.Properties[2].value.tostring()
            Signed = $Event.Properties[3].value.tostring()
            Signature = $Event.Properties[4].value.tostring()
        
 
        }
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType6 -Value ConvertFrom-SysmonDriverLoad -Description “ConvertFrom Sysmon Event type 6 - Driver Loaded”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=6;} | select -first 1
#ConvertFrom-SysmonDriverLoad $SysmonEvent -Verbose