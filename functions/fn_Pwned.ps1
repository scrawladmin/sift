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
            Add-Content -Path datasets.temp -Value $response
            $r = gc datasets.temp
            $r | ForEach-Object {
                if ($_ -like "$hashSuf*" ) {
                    $r = $_.split(':')
                    $result = [pscustomobject]@{
                        PSTypeName = "haveibeenpwned"
                        Dataset    = $r[0]
                        Count      = $r[1]
                    }
                    Write-Host "Match Found " -BackgroundColor Red -ForegroundColor Black 
                    $result   
                } 
            } 
            if (!($result)) {
                Write-Host "No Matching Data Sets" -BackgroundColor Green -ForegroundColor Black 
            }   
            rm datasets.temp    
        }
    }
}
