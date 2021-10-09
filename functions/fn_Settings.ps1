Function Set-Settings {
        #                               logo 
        $script:logo                    = "on"
        #                               log 
        $script:log                     = "$currentdir\log\$logdate.log"
        #                               Ping Flood Count 
        $script:pingcount               = 100
        #                               Ping: Delay between Pings
        $script:pingpause                = 0
        #                               Max Latency(ms)
        $script:maxlatency              = 120
        #                               MTR DNS Server
        $script:DNSServer               = 8.8.8.8
        #                               MXtoolbox API key
        $script:MX_API_key              = ""
        #                               Neutrino user
        $script:neuuserid               = ""
        #                               Neutrino API key
        $script:neuapikey               = ""
        #                               VirusTotal API key
        $script:vtapikey                = ""
        #                               IPstack API key
        $script:ipstackkey              = ""
        #                               Urlscanio API Key
        $script:urlscanapikey           = ""
        #                               Shodan API Key
        $script:shodanapikey            = ""
        #                               Hetrixtools API Key
        $script:hetrixapikey            = ""
        #                               Fraudguard user
        $script:fraudguarduser          = ""
        #                               Fraudguard pass
        $script:fraudguardpass          = ""
}