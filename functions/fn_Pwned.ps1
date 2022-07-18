Function Test-Pwned {
    [cmdletbinding()]
    [OutputType("pwned")]
    param(
        [parameter(Position = 0,
            Mandatory,
            HelpMessage = "Enter an secure string to lookup with haveibeenpwned",
            ValueFromPipeline,
            ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [securestring]$secureString
    )
    $stringAsStream = [System.IO.MemoryStream]::new()
    $writer = [System.IO.StreamWriter]::new($stringAsStream)
    $writer.write($(ConvertFrom-SecureString -SecureString $secureString -AsPlainText))
    $writer.Flush()
    $stringAsStream.Position = 0
    $hash = $(Get-FileHash -Algorithm SHA1 -InputStream $($stringAsStream) | Select-Object Hash).Hash
    $hashPre = $hash.Substring(0, 5)
    $hashSuf = $hash.Substring(5)
    if ($hashPre) {
        try {
            [Net.ServicePointManager]::SecurityProtocol = "Tls12"
            $par = @{
                uri             = $("https://api.pwnedpasswords.com/range/$hashPre")
                UseBasicParsing = $true
            }
            [string]$response = Invoke-RestMethod @par        
        }
        Catch {
            Write-warning "$($_.Exception.Message)" 
            return
        }
        if ($response) {
            $name = 'haveibeenpwned' | Trace-word -words 'haveibeenpwned'
            Add-Content -Path datasets.temp -Value $response -Force
            $d = "datasets.temp"
            $results = @()
             Select-String -Pattern $hashSuf -Path $d | ForEach-Object {
                $_.Line | ForEach-Object {
                    $r = $_ -split ':'
                    $results += new-object psobject -property @{Dataset = $r[0]; Count = $r[1] }
                    Write-log " [haveibeenpwned] $($hash)"
                    Write-log " [haveibeenpwned] $($results)"
                } 
            }
            if (!($results)) {
                Write-Host "No Matching Datasets" -BackgroundColor Green -ForegroundColor Black 
            }
            else {
                Write-Host "Match Found " -BackgroundColor Red -ForegroundColor Black    
                $results 
            }
            rm datasets.temp -Force
        }
    }
}
