function ConvertFrom-SysmonImageLoad {
<#
.Synopsis
ConvertFrom a sysmon Image Load event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals Documentation:
The image loaded event logs when a module is loaded in a specific process. This event is disabled by default and needs 
to be configured with the –l option. It indicates the process in which the module is loaded, hashes and signature 
information. The signature is created asynchronously for performance reasons and indicates if the file was removed 
after loading. This event should be configured carefully, as monitoring all image load events will generate a large 
number of events.


.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=7;} | select -first 1
ConvertFrom-SysmonImageLoad $SysmonEvent

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
        if ($Event.Id -ne 7) {
            Throw ("Event is type {0} - expecting type 7 Image Load event" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
        	Type = 7
            Tag = "ImageLoad"
            Event = "Image loaded"
            UTCTime = $Event.Properties[0].value.tostring()
            ProcessGUID = $Event.Properties[1].value.tostring()
            ProcessId = $Event.Properties[2].value.tostring()
            Image = $Event.Properties[3].value.tostring()
            ImageLoaded = $Event.Properties[4].value.tostring()
            Hashes = $Event.Properties[5].value.tostring()
            Signed = $Event.Properties[6].value.tostring()
            Signiture = $Event.Properties[7].value.tostring()
            SignitureStatus = $Event.Properties[8].value.tostring()
        
        } | select Type,
                    Tag,
                    Event,
                    UTCTime,
                    ProcessGUID,
                    ProcessId,
                    Image,
                    ImageLoaded,
                    Hashes,
                    Signed,
                    Signiture,
                    SignitureStatus
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType7 -Value ConvertFrom-SysmonImageLoad -Description “ConvertFrom Sysmon Event type 7 DLL or Image Loaded by process”
#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=7;} | select -first 1
#ConvertFrom-SysmonImageLoad $SysmonEvent -Verbose