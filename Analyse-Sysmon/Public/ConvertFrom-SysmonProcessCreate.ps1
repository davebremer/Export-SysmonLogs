function ConvertFrom-SysmonProcessCreate {
<#
.Synopsis
ConvertFrom a sysmon process create event

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals doc:
The process creation event provides extended information about a newly created process. 
The full command line provides context on the process execution. The ProcessGUID field is a unique value 
for this process across a domain to make event correlation easier. The hash is a full hash of the file with the 
algorithms in the HashType field.


.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=1;} | select -first 1
ConvertFrom-SysmonProcessCreate $SysmonEvent

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
            [System.Diagnostics.Eventing.Reader.EventLogRecord[]] $Events)

 BEGIN {
    
   }
 
 PROCESS {


    Foreach ($event in $events) { 
       # Write-Verbose ("Event type {0}" -f $Event.Id)

        if ($Event.Id -ne 1) {
            Throw ("Event is type {0} - expecting type 1 Process Create event" -f $Event.Id)
        }
        
        
        New-Object -Type PSObject -Property @{
        	Type = 1
            Tag = "ProcessCreate"
            Event = "Process Creation"
            UTCTime = $Event.Properties[0].value.tostring()
            ProcessGUID = $Event.Properties[1].value.tostring()
            ProcessId = $Event.Properties[2].value.tostring()
            Image = $Event.Properties[3].value.tostring()
            CommandLine = $Event.Properties[4].value.tostring()
            CurrentDirectory = $Event.Properties[5].value.tostring()
            User = $Event.Properties[6].value.tostring()
            LogonGuid=$Event.Properties[7].value.tostring()
            LogonId = $Event.Properties[8].value.tostring()
            TerminalSessionId = $Event.Properties[9].value.tostring()
            IntegrityLevel = $Event.Properties[10].value.tostring()
            Hashes =  $Event.Properties[11].value.tostring()
            ParentProcessId = $Event.Properties[13].value.tostring()
            ParentImage = $Event.Properties[14].value.tostring()
            ParentCommandLine = $Event.Properties[15].value.tostring()
        
        } | select Type,
                    Tag,
                    Event,
                    UTCTime,
                    ProcessGUID,
                    ProcessId,
                    Image,
                    CommandLine,
                    CurrentDirectory,
                    User,
                    LogonGuid,
                    LogonId,
                    TerminalSessionId,
                    IntegrityLevel,
                    Hashes,
                    ParentProcessId,
                    ParentImage,
                    ParentCommandLine
       
    }
  
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType1 -Value ConvertFrom-SysmonProcessCreate -Description “ConvertFrom Sysmon Event type 1 - Process Create”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=1;} | select -first 1
#ConvertFrom-SysmonProcessCreate $SysmonEvent -Verbose
#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=1;} | ConvertFrom-SysmonProcessCreate