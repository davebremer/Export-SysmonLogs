function ConvertFrom-SysmonProcessAccess {
<#
.Synopsis
ConvertFrom a sysmon Process Access event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals Documentation:
The process accesssed event reports when a process opens another process, an operation that’s often followed by 
information queries or reading and writing the address space of the target process. This enables detection of hacking 
tools that read the memory contents of processes like Local Security Authority (Lsass.exe) in order to steal credentials 
for use in Pass-the-Hash attacks. Enabling it can generate significant amounts of logging if there are diagnostic 
utilities active that repeatedly open processes to query their state, so it generally should only be done so with 
filters that remove expected accesses.

.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=10;} | select -first 1
ConvertFrom-SysmonProcessAccess $SysmonEvent

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
        if ($Event.Id -ne 10) {
            Throw ("Event is type {0} - expecting type 10 Process Access event" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
        	Type = 10
            Tag = "ImageLoad"
            Event = "Image loaded"
            UTCTime = $Event.Properties[0].value.tostring()
            SourceProcessGuid = $Event.Properties[1].value.tostring()
            SourceProcessId = $Event.Properties[2].value.tostring()
            SourceThreadId = $Event.Properties[3].value.tostring()
            SourceImage = $Event.Properties[4].value.tostring()
            TargetProcessGuid = $Event.Properties[5].value.tostring()
            TargetProcessId = $Event.Properties[6].value.tostring()
            TargetImage = $Event.Properties[7].value.tostring()
            GrantedAccess = $Event.Properties[8].value.tostring()
            CallTrace = $Event.Properties[9].value.tostring()
           
        } | select Type,
                    Tag,
                    Event,
                    UTCTime,
                    SourceProcessGuid,
                    SourceProcessId,
                    SourceThreadId,
                    SourceImage,
                    TargetProcessGuid,
                    TargetProcessId,
                    TargetImage,
                    GrantedAccess,
                    CallTrace
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType10 -Value ConvertFrom-SysmonProcessAccess -Description “ConvertFrom Sysmon Event type 10 Process Access”
#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=10;} | select -first 1
#ConvertFrom-SysmonProcessAccess $SysmonEvent -Verbose