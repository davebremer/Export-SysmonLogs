function ConvertFrom-SysmonFileCreateStreamHash {
<#
.Synopsis
ConvertFrom a sysmon file create event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 


.EXAMPLE
$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=15;} | select -first 1
ConvertFrom-SysmonFileCreateStreamHash $SysmonEvent

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
        if ($Event.Id -ne 15) {
            Throw ("Event is type {0} - expecting type 15 File Create event" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
            UTCTime = $eventXML.Event.EventData.Data[0].'#text'
            ProcessId = $eventXML.Event.EventData.Data[2].'#text'
            Image = $eventXML.Event.EventData.Data[3].'#text'
            TargetFilename = $eventXML.Event.EventData.Data[4].'#text'
            CreationUtcTime = $eventXML.Event.EventData.Data[5].'#text'
            Hash = $eventXML.Event.EventData.Data[6].'#text'
        }
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType15 -Value ConvertFrom-SysmonFileCreateStreamHash -Description “ConvertFrom Sysmon Event type 1 - Process Create”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=15;} | select -first 1
#ConvertFrom-SysmonFileCreateStreamHash $SysmonEvent -Verbose