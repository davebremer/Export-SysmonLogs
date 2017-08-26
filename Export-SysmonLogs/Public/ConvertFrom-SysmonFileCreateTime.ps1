function ConvertFrom-SysmonFileCreateTime {
<#
.Synopsis
ConvertFrom a sysmon File Create Time Change event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals Documentation:
The change file creation time event is registered when a file creation time is explicitly modified by a process. 
This event helps tracking the real creation time of a file. Attackers may change the file creation time of a backdoor 
to make it look like it was installed with the operating system. Note that many processes legitimately change the 
creation time of a file; it does not necessarily indicate malicious activity.


.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=2;} | select -first 1
ConvertFrom-SysmonFileCreateTime $SysmonEvent

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
        if ($Event.Id -ne 2) {
            Throw ("Event is type {0} - expecting type 2 File Create Time changed" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
        	Type = 2
            Tag = "FileCreateTime"
            Event = "File creation time changed"
            UTCTime = $Event.Properties[0].value.tostring()
            ProcessGUID = $Event.Properties[1].value.tostring()
            ProcessId = $Event.Properties[2].value.tostring()
            Image = $Event.Properties[3].value.tostring()
            TargetFilename = $Event.Properties[4].value.tostring()
            CreationUtcTime = $Event.Properties[5].value.tostring()
            PreviousCreationUtcTime = $Event.Properties[6].value.tostring()
        
        } | select Type,
                    Tag,
                    Event,
                    UTCTime,
                    ProcessId,
                    Image,
                    TargetFilename,
                    CreationUtcTime,
                    PreviousCreationUtcTime
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType2 -Value ConvertFrom-SysmonFileCreateTime -Description “ConvertFrom Sysmon Event type 2 File Create Time Change”
#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=2;} | select -first 1
#ConvertFrom-SysmonFileCreateTime $SysmonEvent -Verbose