function ConvertFrom-SysmonNetworkConnect {
<#
.Synopsis
ConvertFrom a sysmon network event, returning an object with data

.DESCRIPTION
This commandlet takes a sysmon event and returns an object with the data from the event. Useful for further analysis. 

From Sysinternals Documentation:
The network connection event logs TCP/UDP connections on the machine. It is disabled by default. Each connection is linked to a process through the ProcessId and ProcessGUID fields. The event also contains the source and destination host names IP addresses, port numbers and IPv6 status.


.EXAMPLE
$SysmonNetEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=3;} | select -first 1
ConvertFrom-SysmonNetworkConnect $SysmonNetEvent

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
        if ($Event.Id -ne 3) {
            Throw ("Event is type {0} - expecting type 3 Network event" -f $Event.Id)
        }
        # Create Object
    

        New-Object -Type PSObject -Property @{
            UTCTime = $eventXML.Event.EventData.Data[0].'#text'
            ProcessId = $eventXML.Event.EventData.Data[2].'#text'
            Image = $eventXML.Event.EventData.Data[3].'#text'
            User = $eventXML.Event.EventData.Data[4].'#text'
            Protocol = $eventXML.Event.EventData.Data[5].'#text'
            Initiated = $eventXML.Event.EventData.Data[6].'#text'
            SourceIsIpv6=$eventXML.Event.EventData.Data[7].'#text'
            SourceIP = $eventXML.Event.EventData.Data[8].'#text'
            SourceHostname = $eventXML.Event.EventData.Data[9].'#text'
            SourcePort = $eventXML.Event.EventData.Data[10].'#text'
            SourcePortName =  $eventXML.Event.EventData.Data[11].'#text'
            DestinationIsIpv6 = $eventXML.Event.EventData.Data[12].'#text'
            DestinationIP = $eventXML.Event.EventData.Data[13].'#text'
            DestinationHostname = $eventXML.Event.EventData.Data[14].'#text'
            DestinationPort = $eventXML.Event.EventData.Data[15].'#text'
            DestinationPortName = $eventXML.Event.EventData.Data[16].'#text'
 
        }
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType3 -Value ConvertFrom-SysmonNetworkConnect -Description “ConvertFrom Sysmon Event type 3 File Create Time Change”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=3;} | select -first 1
#ConvertFrom-SysmonNetworkConnect $SysmonNetEvent -Verbose