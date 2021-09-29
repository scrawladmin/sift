Function Ping-Flood {
    # -ping
    Param ($ipaddress) 
    If ($psSeven ) {
        $totalLatencyarray = @()
        Write-Log "Ping-Flood"
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
        $totalLatencyarray = @()
        [string]$computername = $ipaddress
        while ($i -le $pingcount) {
            Write-verbose "Test-Connection"
            $pingtime = Test-Connection $computername -Count 1 -ea SilentlyContinue
            start-sleep -Milliseconds $pingpause
            If ($($pingtime.ResponseTime)) {
                Write-verbose "Success"
                $rtt = $($pingtime.ResponseTime)
                $totalLatency = $rtt + $totalLatency
                $totalLatencyarray += $rtt
            }
            Else{
                Write-verbose "loss"
                $totalLatencyarray += 0
                $totalloss++
            }
            $i++

        }
    }
    Submit-Ping
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
    show-graph -datapoints $totalLatencyarray -YAxisTitle "ms" -XAxistitle "Ping" -GraphTitle "Network Latency" -Type Scatter
}