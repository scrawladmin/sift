Function New-Request {
    Param ($object)
    Write-log "Function New-Request $object"
    If ([switch]$ipprobe) {
        Get-neuIPProbe $object
    }
    If ([switch]$ipblocklist) {
        Get-neuIPBlockList $object
    }
    If ([switch]$hostrep) {
        Get-neuHostRep $object
    }
    If ([switch]$ipinfo) {
        Get-neuIPInfo $object
    }
    If ([switch]$urlinfo) {
        Get-neuURLInfo $object
    }
    If ([switch]$emailvalidate) {
        Get-neuEmailvalidate $object
    }
    If ([switch]$emailverify) {
        Get-neuEmailverify $object
    }
    If ([switch]$htmlclean) {
        Get-neuHTMLclean $object
    }
    If ([switch]$traceroute) {
        Test-MTR $target ; ; Start-mtr $target
    }
    If ([switch]$ping) {
        Ping-Flood $ipaddress
    }
    If ([switch]$whois) {
        [string]$ipaddress = $ipaddress
        Get-whois $ipaddress
    }
    If ([switch]$ipreport) {
        [string]$ipaddress = $ipaddress
        Get-VTIPReport $ipaddress
    }
    If ([switch]$urlreport) {
        # [string]$url = $object
        Get-VTURLReport $object -scan
    }
    If ([switch]$filereport) {
        $object = (Get-FileHash $object -Algorithm SHA256).Hash
        Get-VTFileReport $object
    }
    If ([switch]$domainreport) {
        [string]$fqdn = $object
        Get-VTDomainReport $fqdn
    }
    If ([switch]$iplookup) {
        Get-ipstack $object
    }
    If ([switch]$urlscan) {
        Get-urlscanio $object
    }
    If ([switch]$iprep) {
        Get-fraudguardiprep $object
    }
    If ([switch]$ipservices) {
        [string]$ipaddress = $ipaddress
        Get-shodanip $ipaddress
    }
    if ([switch]$ptr) {
        [string]$ipaddress = $ipaddress
        Get-MxLookup -Command ptr -IPAddress $ipaddress
    }
    if ([switch]$mx) {
        [string]$object = $fqdn
        Get-MxLookup -Command mx -Domain $object
    }
    if ([switch]$a) {
        [string]$object = $fqdn
        Get-MxLookup -Command a -Domain $object
    }
    if ([switch]$dns) {
        [string]$object = $fqdn
        Get-MxLookup -Command dns -Domain $object
    }
    if ([switch]$spf) {
        [string]$object = $fqdn
        Get-MxLookup -Command spf -Domain $object
    }
    if ([switch]$txt) {
        [string]$object = $fqdn
        Get-MxLookup -Command txt -Domain $object
    }
    if ([switch]$soa) {
        [string]$object = $fqdn
        Get-MxLookup -Command soa -Domain $object
    }
    if ([switch]$blacklist) {
        [string]$object = $fqdn
        Get-MxLookup -Command blacklist -Domain $object
    }
    If ([switch]$ipblacklist) {
        [string]$ipaddress = $ipaddress
        Get-hetrixIPblacklist $ipaddress
    }
    If ([switch]$fqdnblacklist) {
        Get-hetrixDomainblacklist $object
    }
    If ([switch]$urlquery) {
        Get-URLhausQuery $object
    }
}