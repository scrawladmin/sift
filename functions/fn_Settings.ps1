Function Set-Settings {
        #                               logo 
        $script:logo                    = "on"
        #                               log 
        $script:log                     = "$currentdir\log\$logdate.log"
        #                               Ping Flood Count 
        $script:pingcount               = 100
        #                               Ping: Delay between Pings
        $script:pingpause               = 0
        #                               Max Latency(ms)
        $script:maxlatency              = 120
        #                               MTR DNS Server
        $script:DNSServer               = 1.1.1.1
        #                               Neutrino user
        $script:neutrinokeyuserid       = ""
        #                               Fraudguard user
        $script:fraudguarduserid        = ""
}