<################################################################################################################################################################
.SYNOPSIS
Draws graph in the Powershell console

.DESCRIPTION
Consumes datapoints and draws colored coded fully customizable graph in the Powershell console

.PARAMETER Datapoints
Array of data points which is to be plotted on the graph

.PARAMETER XAxisTitle
Defines text label on x-axis

.PARAMETER YAxisTitle
Defines text label on x-axis

.PARAMETER GraphTitle
Title of the graph

.PARAMETER XAxisStep
Define value of step on x-axis

.PARAMETER YAxisStep
Define value of step on y-axis

.PARAMETER Type
Choose type of the graph [bar, line, scatter]

.PARAMETER ColorMap
Hash table that defines the range of color codes

.PARAMETER HorizontalLines
Add horizontal lines to the graph area

.EXAMPLE
$data = 1..100 | Get-Random -Count 50
Show-Graph -Datapoints $Data -GraphTitle 'CPU'

.EXAMPLE
$data = 1..100 | Get-Random -Count 50
Show-Graph -Datapoints $Data -Type Line

.EXAMPLE
$data = 1..100 | Get-Random -Count 50
Show-Graph -Datapoints $Data -Type Scatter

.EXAMPLE
$data = 1..100 | Get-Random -Count 50
Show-Graph -Datapoints $Data -YAxisTitle "Percentage" -XAxistitle "Time"

.NOTES
Blog: https://RidiCurious.com/
Github: https://github.com/PrateekKumarSingh/Graphical
Author: https://twitter.com/SinghPrateik

Features and Benefits:
- Independent of PowerShell version, and Works on PowerShell Core (Windows\Linux)
- Color-coded output depending upon the Value of data point
- Colors codes can be customized by passing a color-map hash table
- Custom X an Y-Axis labels
- Graph in console is independent and fully customizable, not like Task Manager (Performance Tab)
- Could be incorporated in Powershell scripts
- Can consume data points generated during script run or Pre stored data like in a file or database.

#$Datapoints = (211..278|Get-Random -Count 50)
#Show-Graph -Datapoints $Datapoints -GraphTitle "Avg. CPU utilization" -YAxisTitle "Percent" `
#    -Type Bar -YAxisStep 10 -XAxisStep 10 -AddHorizontalLines -ColorMap @{230 = 'red'; 250 = 'cyan'; 270 = 'green'}
#Show-Graph -Datapoints $Datapoints -XAxisTitle "Avg. CPU utilization" -YAxisTitle "data a lot" `
#    -Type Scatter -YAxisStep 10 -XAxisStep 25 -AddHorizontalLines -ColorMap @{220 = 'red'; 240 = 'cyan'; 270 = 'green'; 290="Blue"}

#>
Function Show-Graph {
    [cmdletbinding()]
    [alias("Graph")]
    Param(
        # Parameter help description
        [Parameter(Mandatory = $true, ValueFromPipeline)] [int[]] $Datapoints,
        [String] $XAxisTitle,
        [String] $YAxisTitle,
        [String] $GraphTitle = 'Untitled',
        [ValidateScript( {
                if ($_ -le 5) {
                    Throw "Can not set XAxisStep less than or equals to 5"
                }
                else {
                    $true
                }
            })] [Int] $XAxisStep = 10,
        [Int] $YAxisStep = 10,
        [ValidateSet("Bar", "Scatter", "Line")] [String] $Type = 'Bar',
        [Hashtable] $ColorMap,
        [Switch] $HorizontalLines,
        $max
    )

    # graph boundary marks
    $TopLeft = [char]9484
    $BottomLeft = [char]9492
    $TopRight = [char]9488
    $BottomRight = [char]9496
    $VerticalEdge = [char]9474
    $TopEdge = $BottomEdge = [char]9472

    # Calculate Max, Min and Range of Y axis
    $NumOfDatapoints = $Datapoints.Count
    $Metric = $Datapoints | Measure-Object -Maximum -Minimum
    if ($command -eq 'stats') { 
        $EndofRange = 100
        $StartOfRange = 0

    }
    if ([switch]$ping) {
        Write-Verbose "$totalmax -gt $maxlatency"
        Write-Verbose "totalmax: $totalmax"
        if (  ( [int]$totalmax -gt [int]$maxlatency) -eq $true) {
            $EndofRange = $totalmax  
            $StartOfRange = $totalmax / 2
        }
        else {
            $EndofRange = 100 
            $StartOfRange = 0
        }
        Write-Verbose "End: $EndofRange start: $StartOfRange"
    }
    Else {
        $EndofRange = $Metric.Maximum + ($YAxisStep - $Metric.Maximum % $YAxisStep)
        $StartOfRange = $Metric.Minimum - ($Metric.Minimum % $YAxisStep)
    }

    $difference = $EndofRange - $StartOfRange
    $NumOfRows = $difference / ($YAxisStep)

    # Calculate label lengths
    $NumOfLabelsOnYAxis = $NumOfRows
    $LengthOfMaxYAxisLabel = (($Datapoints | Measure-Object -Maximum).Maximum).tostring().length
    
    $YAxisTitleAlphabetCounter = 0
    $YAxisTitleStartIdx, $YAxisTitleEndIdx = CenterAlignStringReturnIndices -String $YAxisTitle -Length $NumOfRows
    
    If ($YAxisTitle.Length -gt $NumOfLabelsOnYAxis) {
        Write-Warning "No. Alphabets in YAxisTitle [$($YAxisTitle.Length)] can't be greator than no. of Labels on Y-Axis [$NumOfLabelsOnYAxis]"
        Write-Warning "YAxisTitle will be cropped"
    }
    
    # Create a 2D Array to save datapoints  in a 2D format
    switch ($Type) {
        'Bar' { $Array = Get-BarPlot -Datapoints $Datapoints -Step $YAxisStep -StartOfRange $StartOfRange -EndofRange $EndofRange }
        'Scatter' { $Array = Get-ScatterPlot -Datapoints $Datapoints -Step $YAxisStep -StartOfRange $StartOfRange -EndofRange $EndofRange }
        'Line' { $Array = Get-LinePlot -Datapoints $Datapoints -Step $YAxisStep -StartOfRange $StartOfRange -EndofRange $EndofRange }
    }
    
    # Preparing the step markings on the X-Axis
    $Increment = $XAxisStep
    $XAxisLabel = " " * ($LengthOfMaxYAxisLabel + 4)
    $XAxis = " " * ($LengthOfMaxYAxisLabel + 3) + [char]9492
    
    For ($Label = 1; $Label -le $NumOfDatapoints; $Label++) {
        if ([math]::floor($Label / $XAxisStep) ) {
            $XAxisLabel += $Label.tostring().PadLeft($Increment)
            $XAxis += ([char]9516).ToString()
            $XAxisStep += $Increment
        }
        else {
            $XAxis += [Char]9472
        }
    }

    # calculate boundaries of the graph
    $TopBoundaryLength = $XAxis.Length - $GraphTitle.Length
    $BottomBoundaryLength = $XAxis.Length + 2
    
    # draw top boundary
    [string]::Concat($TopLeft, " ", $GraphTitle, " ", $([string]$TopEdge * $TopBoundaryLength), $TopRight)
    [String]::Concat($VerticalEdge, $(" " * $($XAxis.length + 2)), $VerticalEdge) # extra line to add space between top-boundary and the graph
    
    # draw the graph
    For ($i = $NumOfRows; $i -gt 0; $i--) {
        $Row = ''
        For ($j = 0; $j -lt $NumOfDatapoints; $j++) {
            $Cell = $Array[$i, $j]
            if ([String]::IsNullOrWhiteSpace($Cell)) {
                if ($AddHorizontalLines) {
                    $String = [Char]9472
                }
                else {
                    $String = ' '
                }
                #$String = [Char]9532
            }
            else {
                $String = $Cell
            }
            $Row = [string]::Concat($Row, $String)
        }
        
        $YAxisLabel = $StartOfRange + $i * $YAxisStep
        
        
        # add Y-Axis title alphabets if it exists in a row
        If ($i -in $YAxisTitleStartIdx..$YAxisTitleEndIdx -and $YAxisTitle) {
            $YAxisLabelAlphabet = $YAxisTitle[$YAxisTitleAlphabetCounter]
            $YAxisTitleAlphabetCounter++
        }
        else {
            $YAxisLabelAlphabet = ' '
        }
        

        If ($ColorMap) {

            $Keys = $ColorMap.Keys | Sort-Object
            $LowerBound = $StartOfRange
            $Map = @()

            $Map += For ($k = 0; $k -lt $Keys.count; $k++) {
                [PSCustomObject]@{
                    LowerBound = $LowerBound
                    UpperBound = $Keys[$k]
                    Color      = $ColorMap[$Keys[$k]]
                }
                $LowerBound = $Keys[$k] + 1
            }
            
            $Color = $Map.ForEach( {
                    if ($YAxisLabel -in $_.LowerBound..$_.UpperBound) {
                        $_.Color
                    }
                })

            if ([String]::IsNullOrEmpty($Color)) { $Color = "White" }
            
            Write-Graph $YAxisLabelAlphabet $YAxisLabel $Row $Color 'DarkYellow'

        }
        else {
            # Default coloring mode divides the datapoints in percentage range
            # and color code them automatically 
            # i.e, 
            # 1-40% -> Green
            # 41-80% -> Yellow
            # 81-100% -> Red

            $RangePercent = $i / $NumOfRows * 100
            # To color the graph depending upon the datapoint value
            If ($RangePercent -gt 80) {
                Write-Graph $YAxisLabelAlphabet $YAxisLabel $Row 'Red' 'DarkYellow'
            }
            elseif ($RangePercent -le 80 -and $RangePercent -gt 40) {
                Write-Graph $YAxisLabelAlphabet $YAxisLabel $Row 'Yellow' 'DarkYellow' 
            }
            elseif ($RangePercent -le 40 -and $RangePercent -ge 1) {
                Write-Graph $YAxisLabelAlphabet $YAxisLabel $Row 'Green' 'DarkYellow'
            }
            else {
                #Write-Host "$YAxisLabel|"
                #Write-Host "$($YAxisLabel.PadLeft($LengthOfMaxYAxisLabel+2))|"
            }
        }
        
    }
    
    # draw bottom boundary
    $XAxisLabel += " " * ($XAxis.Length - $XAxisLabel.Length) # to match x-axis label length with x-axis length
    [String]::Concat($VerticalEdge, $XAxis, "  ", $VerticalEdge) # Prints X-Axis horizontal line
    [string]::Concat($VerticalEdge, $XAxisLabel, "  ", $VerticalEdge) # Prints X-Axis step labels

    
    if (![String]::IsNullOrWhiteSpace($XAxisTitle)) {
        # Position the x-axis label at the center of the axis
        $XAxisTitle = " " * $LengthOfMaxYAxisLabel + (CenterAlignString $XAxisTitle $XAxis.Length)        
        Write-Host $VerticalEdge -NoNewline
        Write-Host $XAxisTitle -ForegroundColor DarkYellow -NoNewline # Prints XAxisTitle
        Write-Host $(" " * $(($LengthOfMaxYAxisLabel + $XAxis.length) - $XAxisTitle.Length - 2)) $VerticalEdge
    }
    
    # bottom boundary
    [string]::Concat($BottomLeft, $([string]$BottomEdge * $BottomBoundaryLength), $BottomRight)
    
}

Function Get-BarPlot {
    [cmdletbinding()]
    [alias("bar")]
    Param(
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [int[]] $Datapoints,
        [int] $StartOfRange,
        [int] $EndofRange,
        [int] $Step = 10
    )
    $Difference = $EndofRange - $StartOfRange

    $NumOfDatapoints = $Datapoints.Count
    $HalfStep = [Math]::Ceiling($Step / 2)
    $Marker = [char] 9608

    # Create a 2D Array to save datapoints  in a 2D format
    $NumOfRows = $difference / ($Step) + 1
    $Array = New-Object 'object[,]' $NumOfRows, $NumOfDatapoints

    For ($i = 0; $i -lt $Datapoints.count; $i++) {
        # Fit datapoint in a row, where, a row's data range = Total Datapoints / Step
        $RowIndex = [Math]::Ceiling($($Datapoints[$i] - $StartOfRange) / $Step)
        # use a half marker is datapoint falls in less than equals half of the step
        $HalfMark = $Datapoints[$i] % $Step -in $(1..$HalfStep)
        
        if ($HalfMark) {
            $Array[($RowIndex), $i] = [char] 9604
        }
        else {
            $Array[($RowIndex), $i] = $Marker
        }
        
        # To get a bar fill all the same row indices of 2D array under and including datapoint
        For ($j = 0; $j -lt $RowIndex; $j++) {
            $Array[$j, $i] = $Marker
        }
    }

    # return the 2D array of plots
    return , $Array
}
Function Get-LinePlot {
    [cmdletbinding()]
    [alias("line")]
    Param(
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [int[]] $Datapoints,
        [int] $StartOfRange,
        [int] $EndofRange,
        [int] $Step = 10
    )
    $Difference = $EndofRange - $StartOfRange
    $NumOfDatapoints = $Datapoints.Count

    
    # Create a 2D Array to save datapoints  in a 2D format
    $NumOfRows = $difference / ($Step) + 1
    $Array = New-Object 'object[,]' $NumOfRows, $NumOfDatapoints

    $Marker = [char] 9608
    $Line = [char] 9616

    For ($i = 0; $i -lt $Datapoints.count; $i++) {
        # Fit datapoint in a row, where, a row's data range = Total Datapoints / Step
        $RowIndex = [Math]::Ceiling($($Datapoints[$i] - $StartOfRange) / $Step) 
        $RowIndexNextItem = [Math]::Ceiling($($Datapoints[$i + 1] - $StartOfRange) / $Step)

        # to decide the direction of line joining two data points
        if ($RowIndex -gt $RowIndexNextItem) {
            Foreach ($j in $($RowIndex - 1)..$($RowIndexNextItem + 1)) {
                $Array[$j, $i] = $Line # add line
            }
        }
        elseif ($RowIndex -lt $RowIndexNextItem) {
            Foreach ($j in $($RowIndex)..$($RowIndexNextItem - 1)) {
                $Array[$j, $i] = $Line # add line
            }
        }
        $Array[$RowIndex, $i] = [char] $Marker # data point
    }
    # return the 2D array of plots
    return , $Array
}
Function Get-ScatterPlot {
    [cmdletbinding()]
    [alias("scatter")]
    Param(
        # Parameter help description
        [Parameter(Mandatory = $true)]
        [int[]] $Datapoints,
        [int] $StartOfRange,
        [int] $EndofRange,
        [int] $Step = 10
        #[ValidateSet("square","dot","triangle")] [String] $Marker = 'dot'
    )

    # Create a 2D Array to save datapoints  in a 2D format
    $Difference = $EndofRange - $StartOfRange
    $NumOfRows = $difference / ($Step) + 1
    $NumOfDatapoints = $Datapoints.Count
    $Array = New-Object 'object[,]' ($NumOfRows), $NumOfDatapoints


    For ($i = 0; $i -lt $Datapoints.count; $i++) {
        # Fit datapoint in a row, where, a row's data range = Total Datapoints / Step
        $RowIndex = [Math]::Ceiling($($Datapoints[$i] - $StartOfRange) / $Step) 

        # use a half marker is datapoint falls in less than equals half of the step
        $LowerHalf = $Datapoints[$i] % $Step -in $(1..$HalfStep)
        
        if ($LowerHalf) {
            try {
            $Array[$RowIndex, $i] = [char] 9604
            }
            Catch {
            }
        }
        else {
            try {
                $Array[$RowIndex, $i] = [char] 9600
            }
            Catch {
                #$_.Exception.Message
            }
        }
        
    }

    # return the 2D array of plots
    return , $Array
}
Function CenterAlignString ($String, $Length) {
    $Padding = [math]::Round( $Length / 2 + [math]::round( $String.length / 2)  )
    return $String.PadLeft($Padding)
}
Function CenterAlignStringReturnIndices ($String, $Length) {
    $StartIdx = [Math]::Round(($Length + ($String.Length - 1)) / 2 )
    $EndIdx = $StartIdx - ($String.Length - 1)
    return $StartIdx, $EndIdx
}

Function Write-Graph($YAxisLabelAlphabet, $YAxisLabel, $Row, $RowColor, $LabelColor) {
    Write-Host $([char]9474) -NoNewline
    Write-Host $YAxisLabelAlphabet -ForegroundColor $LabelColor -NoNewline
    Write-Host "$($YAxisLabel.tostring().PadLeft($LengthOfMaxYAxisLabel+2) + [Char]9508)" -NoNewline
    ##Write-Host "$YAxisLabel|" -NoNewline
    Write-Host $Row -ForegroundColor $RowColor -NoNewline
    Write-Host " " $([char]9474) 
}