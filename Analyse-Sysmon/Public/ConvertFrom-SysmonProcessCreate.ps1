function ConvertFrom-SysmonProcessCreate {
<#
.Synopsis
ConvertFrom a sysmon process create event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals doc:
The process creation event provides extended information about a newly created process. The full command line provides context on the process execution. The ProcessGUID field is a unique value for this process across a domain to make event correlation easier. The hash is a full hash of the file with the algorithms in the HashType field.


.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=1;} | select -first 1
ConvertFrom-SysmonProcessCreate $SysmonEvent

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
        $eventXML = [xml]$Event.ToXml()
        Write-Verbose ("Event type {0}" -f $Event.Id)
        if ($Event.Id -ne 1) {
            Throw ("Event is type {0} - expecting type 1 Process Create event" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
            UTCTime = $eventXML.Event.EventData.Data[0].'#text'
            ProcessId = $eventXML.Event.EventData.Data[2].'#text'
            Image = $eventXML.Event.EventData.Data[3].'#text'
            CommandLine = $eventXML.Event.EventData.Data[4].'#text'
            CurrentDirectory = $eventXML.Event.EventData.Data[5].'#text'
            User = $eventXML.Event.EventData.Data[6].'#text'
            LogonGuid=$eventXML.Event.EventData.Data[7].'#text'
            LogonId = $eventXML.Event.EventData.Data[8].'#text'
            TerminalSessionId = $eventXML.Event.EventData.Data[9].'#text'
            IntegrityLevel = $eventXML.Event.EventData.Data[10].'#text'
            Hashes =  $eventXML.Event.EventData.Data[11].'#text'
            ParentProcessId = $eventXML.Event.EventData.Data[13].'#text'
            ParentImage = $eventXML.Event.EventData.Data[14].'#text'
            ParentCommandLine = $eventXML.Event.EventData.Data[15].'#text'
        
        }
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType1 -Value ConvertFrom-SysmonProcessCreate -Description “ConvertFrom Sysmon Event type 1 - Process Create”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=1;} | select -first 1
#ConvertFrom-SysmonProcessCreate $SysmonEvent -Verbose