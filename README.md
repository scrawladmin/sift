NAME
    sift

SYNOPSIS
    A collection of PowerShell scripts to utilize 3rd party APIs and research IPs, URLs, and Domains


SYNTAX
    sift [[-ipaddress] <IPAddress[]>] [[-ipblocklist]] [[-ipprobe]] [[-hostrep]] [[-ipinfo]] [[-ping]]
    [[-whois]] [[-ipreport]] [[-iplookup]] [[-iprep]] [[-ipservices]] [[-ptr]] [[-ipblacklist]] [[-whoblacklist]] [[-ippulse]] [-raw]
    [<CommonParameters>]

    sift [[-fqdn] <String[]>] [[-hostrep]] [[-domainreport]] [[-hostnamerep]] [[-mx]] [[-a]] [[-dns]]
    [[-whoisapi]] [[-spf]] [[-txt]] [[-soa]] [[-blacklist]] [[-fqdnblacklist]] [[-fqdnpulse]] [[-domainscore]] [[-domainscorecheck]] [-raw]
    [<CommonParameters>]

    sift [[-target] <Object>] [[-traceroute]] [-raw] [<CommonParameters>]

    sift [[-url] <String[]>] [[-hostrep]] [[-urlinfo]] [[-urlreport]] [[-urlscan]] [[-urlquery]]
    [[-urlsubmit]] [-raw] [<CommonParameters>]

    sift [[-filepath] <String[]>] [[-filereport]] [-raw] [<CommonParameters>]

    sift [[-email] <String[]>] [[-emailvalidate]] [[-emailverify]] [-raw] [<CommonParameters>]

    sift [[-html] <String[]>] [[-htmlclean]] [-raw] [<CommonParameters>]

    sift [[-addkey]] [[-neutrino]] [[-virustotal]] [[-ipstack]] [[-urlscanio]] [[-shodan]] [[-hetrix]]
    [[-fraudguard]] [[-mxtoolbox]] [[-urlhaus]] [[-whoapi]] [-raw] [<CommonParameters>]

    sift [[-pwned]] [-raw] [<CommonParameters>]

    sift [[-phone] <Int64>] [-raw] [<CommonParameters>]

    sift [[-unlock]] [-raw] [<CommonParameters>]


DESCRIPTION


RELATED LINKS
    https://github.com/scrawladmin/sift

REMARKS
    To see the examples, type: "Get-Help sift -Examples"
    For more information, type: "Get-Help sift -Detailed"
    For technical information, type: "Get-Help sift -Full"
    For online help, type: "Get-Help sift -Online"
