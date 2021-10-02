Function Ping-Flood {
    [cmdletbinding()]
    [OutputType("ping")]
    Param (
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Enter an IPV4 address to send Ping Flood",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern("^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])){3}$")]    
        $ipaddress
    ) 
    Begin {
        $totalLatencyarray = @()
        Write-Log "Ping-Flood"
    }
    Process {
        If ($psSeven ) {
            $totalLatencyarray = @()
            while ($i -lt $pingcount) {
                $pingtime = Test-Connection $ipaddress -Count 1 -ea SilentlyContinue
                Start-Sleep -Milliseconds $pingpause
                If ($pingtime.Status -eq "Success") {
                    $successPing++
                    $totalLatencyarray += $pingtime.Latency
                    $totalLatency = $pingtime.Latency + $totalLatency
                }
                Else {
                    $totalloss++
                }
                $i++
            }
        }
        ElseIf (!$psSeven) {
            $global:ProgressPreference = "SilentlyContinue"
            while ($i -le $pingcount) {
                Write-verbose "Test-Connection"
                $pingtime = Test-Connection $ipaddress -Count 1 -ea SilentlyContinue
                start-sleep -Milliseconds $pingpause
                If ($($pingtime.ResponseTime)) {
                    Write-verbose "Success"
                    $rtt = $($pingtime.ResponseTime)
                    $totalLatency = $rtt + $totalLatency
                    $totalLatencyarray += $rtt
                }
                Else {
                    Write-verbose "loss"
                    $totalLatencyarray += 0
                    $totalloss++
                }
                $i++

            }
        }
    }
    End {
        Submit-Ping
    }
}
Function Submit-Ping {
    write-log "Function Submit-Ping"
    if ($psseven) {
        $totalminmax = $totalLatencyarray | measure -AllStats
        Write-verbose "Count:           $($totalminmax.Count)"
        Write-verbose "Average:         $($totalminmax.Average)"
        Write-verbose "Sum:             $($totalminmax.Sum)"
        Write-verbose "Maximum:         $($totalminmax.Maximum)"
        Write-verbose "Minimum:         $($totalminmax.Minimum)"
        Write-verbose "StandardDeviation:       $($totalminmax.StandardDeviation)"
        $script:totalmax = ($totalminmax).Maximum
        $script:totalmin = $totalmin = ($totalminmax).Minimum
        $totalAvg = ($totalminmax).Average
    }
    Else {
        $totalAvg = ($totalLatencyarray | measure -Average).Average
        $script:totalmax = ($totalLatencyarray | measure -Maximum).Maximum
        $totalmin = ($totalLatencyarray | measure -Minimum).Minimum
        Write-verbose "Average:         $totalAvg"
        Write-verbose "Maximum:         $totalmax"
        Write-verbose "Minimum:         $totalmin"
    }
    $loss = 100 * ($totalloss / $($pingcount))
    $totalLatency = $totalLatency / $pingcount
    $totalAvg = [math]::Round($totalAvg)
    $totals = @("Latency = Avg: $totalAvg Max: $totalmax Min: $totalmin Loss = $loss%") 
    Write-log "$totals"
    show-graph -datapoints $totalLatencyarray -YAxisTitle "ms" -XAxistitle "Ping" -GraphTitle "Network Latency" -Type Scatter
}