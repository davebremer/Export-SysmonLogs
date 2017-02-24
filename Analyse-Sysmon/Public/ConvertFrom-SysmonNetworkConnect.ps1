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
        	Type = 3
            Tag = "NetworkConnect"
            Event = "Network connection detected"
            UTCTime = $Event.Properties[0].value.tostring()
            ProcessId = $Event.Properties[2].value.tostring()
            Image = $Event.Properties[3].value.tostring()
            User = $Event.Properties[4].value.tostring()
            Protocol = $Event.Properties[5].value.tostring()
            Initiated = $Event.Properties[6].value.tostring()
            SourceIsIpv6=$Event.Properties[7].value.tostring()
            SourceIP = $Event.Properties[8].value.tostring()
            SourceHostname = $Event.Properties[9].value.tostring()
            SourcePort = $Event.Properties[10].value.tostring()
            SourcePortName =  $Event.Properties[11].value.tostring()
            DestinationIsIpv6 = $Event.Properties[12].value.tostring()
            DestinationIP = $Event.Properties[13].value.tostring()
            DestinationHostname = $Event.Properties[14].value.tostring()
            DestinationPort = $Event.Properties[15].value.tostring()
            DestinationPortName = $Event.Properties[16].value.tostring()
 
        } | select Type,
                    Tag,
                    Event,
                    UTCTime,
                    ProcessId,
                    Image,
                    User,
                    Protocol,
                    Initiated,
                    SourceIsIpv6,
                    SourceIP,
                    SourceHostname,
                    SourcePort,
                    SourcePortName,
                    DestinationIsIpv6,
                    DestinationIP,
                    DestinationHostname,
                    DestinationPort,
                    DestinationPortName
    }
}

END {}

}
Set-Alias -Name ConvertFrom-SysmonType3 -Value ConvertFrom-SysmonNetworkConnect -Description “ConvertFrom Sysmon Event type 3 File Create Time Change”

#$SysmonEvent = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-Sysmon/Operational";Id=3;} | select -first 1
#ConvertFrom-SysmonNetworkConnect $SysmonNetEvent -Verbose