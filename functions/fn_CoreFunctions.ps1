Function Get-Logo {
    Write-log "Function: Get-Logo"  
    Write-Host "
    _________.__  _____  __   
   /   _____/|__|/ ____\/  |_ 
   \_____  \ |  \   __\\   __\
   /        \|  ||  |   |  |  
  /_______  /|__||__|   |__|  
          \/                  
" -F C
}
Function Set-Console {
    Write-log "Function: Set-Console"
    If ( $logo -ne "off") {
        Clear-Host
        $host.ui.RawUi.WindowTitle = "...::: Sift :::..."
        [console]::ForegroundColor = "White"
        [console]::BackgroundColor = "Black"
        $host.PrivateData.VerboseForegroundColor = 'White'
        # [console]::WindowWidth = 150; [console]::WindowHeight = 125; [console]::BufferWidth = [console]::WindowWidth
        #$host.UI.RawUI.BufferSize = New-Object System.Management.Automation.Host.Size(200,5000)
        Get-Logo
    }
    Else {
        $host.ui.RawUi.WindowTitle = "...::: Sift :::..."
        [console]::ForegroundColor = "White"
        [console]::BackgroundColor = "Black"
        $host.PrivateData.VerboseForegroundColor = 'White'
    }
}
Function Write-log {
    param ($logmessage)
    if ($log) {
        Add-Content $log "[$loggingdate] $logmessage "
    }
    if ($PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent) {
        Write-Verbose "$logmessage"
    }
}

Function Test-PSversion {
    Write-Log "Function Test-PSversion"
    $psSeven = ( $PSVersionTable.PSVersion.Major -eq 7 ) 
    If ($psSeven -eq $true ) {
        $script:psSeven = 1
    }
    Else {
        $script:psSeven = $null
    }
}


Function Trace-Word {
    [Cmdletbinding()]
    [Alias("Highlight")]
    Param(
        [Parameter(ValueFromPipeline = $true, Position = 0)] [string[]] $content,
        [Parameter(Position = 1)] 
        [ValidateNotNull()]
        [String[]] $words = $(throw "Provide word[s] to be highlighted!")
    )
    
    Begin {
        
        $Color = @{       
            0  = 'Yellow'      
            1  = 'Magenta'     
            2  = 'Red'         
            3  = 'Cyan'        
            4  = 'Green'       
            5  = 'Blue'        
            6  = 'DarkGray'    
            7  = 'Gray'        
            8  = 'DarkYellow'    
            9  = 'DarkMagenta'    
            10 = 'DarkRed'     
            11 = 'DarkCyan'    
            12 = 'DarkGreen'    
            13 = 'DarkBlue'        
        }

        $ColorLookup = @{}

        For ($i = 0; $i -lt $words.count ; $i++) {
            if ($i -eq 13) {
                $j = 0
            }
            else {
                $j = $i
            }

            $ColorLookup.Add($words[$i], $Color[$j])
            $j++
        }
        
    }
    Process {
        $content | ForEach-Object {
    
            $TotalLength = 0
               
            $_.split() | `
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ` #Filter-out whiteSpaces
            ForEach-Object {
                if ($TotalLength -lt ($Host.ui.RawUI.BufferSize.Width - 10)) {
                    #"TotalLength : $TotalLength"
                    $Token = $_
                    $displayed = $False
                            
                    Foreach ($Word in $Words) {
                        if ($Token -like "*$Word*") {
                            $Before, $after = $Token -Split "$Word"
                              
                                        
                            #"[$Before][$Word][$After]{$Token}`n"
                                    
                            Write-Host $Before -NoNewline ; 
                            Write-Host $Word -NoNewline -Fore Black -Back $ColorLookup[$Word];
                            Write-Host $after -NoNewline ; 
                            $displayed = $true                                   
                            #Start-Sleep -Seconds 1    
                            #break  
                        }

                    } 
                    If (-not $displayed) {   
                        Write-Host "$Token " -NoNewline                                    
                    }
                    else {
                        Write-Host " " -NoNewline  
                    }
                    $TotalLength = $TotalLength + $Token.Length + 1
                }
                else {                      
                    Write-Host '' #New Line  
                    $TotalLength = 0 

                }

                #Start-Sleep -Seconds 0.5
                        
            }
            Write-Host '' #New Line               
        }
    }
    end
    {    }

}
#Trace-Word -content (Get-Content iis.log) -words "IIS", 's', "exe", "10", 'system'

function Select-ColorString {
    <#
   .SYNOPSIS

   Find the matches in a given content by the pattern and write the matches in color like grep.

   .NOTES

   inspired by: https://ridicurious.com/2018/03/14/highlight-words-in-powershell-console/

   .EXAMPLE

   > 'aa bb cc', 'A line' | Select-ColorString a

   Both line 'aa bb cc' and line 'A line' are displayed as both contain "a" case insensitive.

   .EXAMPLE

   > 'aa bb cc', 'A line' | Select-ColorString a -NotMatch

   Nothing will be displayed as both lines have "a".

   .EXAMPLE

   > 'aa bb cc', 'A line' | Select-ColorString a -CaseSensitive

   Only line 'aa bb cc' is displayed with color on all occurrences of "a" case sensitive.

   .EXAMPLE

   > 'aa bb cc', 'A line' | Select-ColorString '(a)|(\sb)' -CaseSensitive -BackgroundColor White

   Only line 'aa bb cc' is displayed with background color White on all occurrences of regex '(a)|(\sb)' case sensitive.

   .EXAMPLE

   > 'aa bb cc', 'A line' | Select-ColorString b -KeepNotMatch

   Both line 'aa bb cc' and 'A line' are displayed with color on all occurrences of "b" case insensitive,
   and for lines without the keyword "b", they will be only displayed but without color.

   .EXAMPLE

   > Get-Content app.log -Wait -Tail 100 | Select-ColorString "error|warning|critical" -MultiColorsForSimplePattern -KeepNotMatch

   Search the 3 key words "error", "warning", and "critical" in the last 100 lines of the active file app.log and display the 3 key words in 3 colors.
   For lines without the keys words, hey will be only displayed but without color.

   .EXAMPLE

   > Get-Content "C:\Windows\Logs\DISM\dism.log" -Tail 100 -Wait | Select-ColorString win

   Find and color the keyword "win" in the last ongoing 100 lines of dism.log.

   .EXAMPLE

   > Get-WinEvent -FilterHashtable @{logname='System'; StartTime = (Get-Date).AddDays(-1)} | Select-Object time*,level*,message | Select-ColorString win

   Find and color the keyword "win" in the System event log from the last 24 hours.
   #>

    [Cmdletbinding(DefaultParametersetName = 'Match')]
    param(
        [Parameter(
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]$Pattern = $(throw "$($MyInvocation.MyCommand.Name) : " `
                + "Cannot bind null or empty value to the parameter `"Pattern`""),

        [Parameter(
            ValueFromPipeline = $true,
            HelpMessage = "String or list of string to be checked against the pattern")]
        [String[]]$Content,

        [Parameter()]
        [ValidateSet(
            'Black',
            'DarkBlue',
            'DarkGreen',
            'DarkCyan',
            'DarkRed',
            'DarkMagenta',
            'DarkYellow',
            'Gray',
            'DarkGray',
            'Blue',
            'Green',
            'Cyan',
            'Red',
            'Magenta',
            'Yellow',
            'White')]
        [String]$ForegroundColor = 'Black',

        [Parameter()]
        [ValidateSet(
            'Black',
            'DarkBlue',
            'DarkGreen',
            'DarkCyan',
            'DarkRed',
            'DarkMagenta',
            'DarkYellow',
            'Gray',
            'DarkGray',
            'Blue',
            'Green',
            'Cyan',
            'Red',
            'Magenta',
            'Yellow',
            'White')]
        [ValidateScript( {
                if ($Host.ui.RawUI.BackgroundColor -eq $_) {
                    throw "Current host background color is also set to `"$_`", " `
                        + "please choose another color for a better readability"
                }
                else {
                    return $true
                }
            })]
        [String]$BackgroundColor = 'White',

        [Parameter()]
        [Switch]$CaseSensitive,

        [Parameter(
            HelpMessage = "Available only if the pattern is simple non-regex string " `
                + "separated by '|', use this switch with fast CPU.")]
        [Switch]$MultiColorsForSimplePattern,

        [Parameter(
            ParameterSetName = 'NotMatch',
            HelpMessage = "If true, write only not matching lines; " `
                + "if false, write only matching lines")]
        [Switch]$NotMatch,

        [Parameter(
            ParameterSetName = 'Match',
            HelpMessage = "If true, write all the lines; " `
                + "if false, write only matching lines")]
        [Switch]$KeepNotMatch
    )

    begin {
        $paramSelectString = @{
            Pattern       = $Pattern
            AllMatches    = $true
            CaseSensitive = $CaseSensitive
        }
        $writeNotMatch = $KeepNotMatch -or $NotMatch

        [System.Collections.ArrayList]$colorList = [System.Enum]::GetValues([System.ConsoleColor])
        $currentBackgroundColor = $Host.ui.RawUI.BackgroundColor
        $colorList.Remove($currentBackgroundColor.ToString())
        $colorList.Remove($ForegroundColor)
        $colorList.Reverse()
        $colorCount = $colorList.Count

        if ($MultiColorsForSimplePattern) {
            # Get all the console foreground and background colors mapping display effet:
            # https://gist.github.com/timabell/cc9ca76964b59b2a54e91bda3665499e
            $patternToColorMapping = [Ordered]@{}
            # Available only if the pattern is a simple non-regex string separated by '|', use this with fast CPU.
            # We dont support regex as -Pattern for this switch as it will need much more CPU.
            # This switch is useful when you need to search some words,
            # for example searching "error|warn|crtical" these 3 words in a log file.
            $expectedMatches = $Pattern.split("|")
            $expectedMatchesCount = $expectedMatches.Count
            if ($expectedMatchesCount -ge $colorCount) {
                Write-Host "The switch -MultiColorsForSimplePattern is True, " `
                    + "but there're more patterns than the available colors number " `
                    + "which is $colorCount, so rotation color list will be used." `
                    -ForegroundColor Yellow
            }
            0..($expectedMatchesCount - 1) | % {
                $patternToColorMapping.($expectedMatches[$_]) = $colorList[$_ % $colorCount]
            }

        }
    }

    process {
        foreach ($line in $Content) {
            $matchList = $line | Select-String @paramSelectString

            if (0 -lt $matchList.Count) {
                if (-not $NotMatch) {
                    $index = 0
                    foreach ($myMatch in $matchList.Matches) {
                        $length = $myMatch.Index - $index
                        Write-Host $line.Substring($index, $length) -NoNewline

                        $expectedBackgroupColor = $BackgroundColor
                        if ($MultiColorsForSimplePattern) {
                            $expectedBackgroupColor = $patternToColorMapping[$myMatch.Value]
                        }

                        $paramWriteHost = @{
                            Object          = $line.Substring($myMatch.Index, $myMatch.Length)
                            NoNewline       = $true
                            ForegroundColor = $ForegroundColor
                            BackgroundColor = $expectedBackgroupColor
                        }
                        Write-Host @paramWriteHost

                        $index = $myMatch.Index + $myMatch.Length
                    }
                    Write-Host $line.Substring($index)
                }
            }
            else {
                if ($writeNotMatch) {
                    Write-Host "$line"
                }
            }
        }
    }

    end {
    }
}
