function Write-ToLogFile {
    <#
        .SYNOPSIS
            Save output to a log file

        .DESCRIPTION
            Overload function for Write-Output that writes a string to both the console
            and a persistent log file. Creates the log directory if it does not exist.

        .PARAMETER StringObject
            The message string to write to the console and log file.

        .PARAMETER LogDirectory
            Full path to the directory where the log file will be stored.
            Defaults to ".\Logs".

        .EXAMPLE
            Write-ToLogFile "$(Get-TimeStamp) Connecting to IPPS session"

        .EXAMPLE
            Write-ToLogFile -StringObject "$(Get-TimeStamp) Export complete" -LogDirectory "C:\Reports\Logs"

        .NOTES
            Depends on Get-TimeStamp for formatted timestamps.
    #>

    [OutputType('System.String')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$StringObject,

        [Parameter()]
        [string]$LogDirectory = ".\Logs",

        [Parameter()]
        [System.ConsoleColor]$ForegroundColor
    )

    process {
        if (-not (Test-Path -Path $LogDirectory)) {
            if ($PSCmdlet.ShouldProcess($LogDirectory, "Create logging directory")) {
                try {
                    New-Item -Path $LogDirectory -ItemType Directory -ErrorAction Stop | Out-Null
                }
                catch {
                    Write-Output "$(Get-TimeStamp) ERROR: Could not create log directory '$LogDirectory': $_"
                    return
                }
            }
        }

        try {
            if ($PSBoundParameters.ContainsKey('ForegroundColor')) {
                Write-Host $StringObject -ForegroundColor $ForegroundColor
            }
            else {
                Write-Host $StringObject
            }
            Out-File -FilePath (Join-Path $LogDirectory "Logging.txt") -InputObject $StringObject -Encoding utf8 -Append -ErrorAction Stop
        }
        catch {
            Write-Output "$(Get-TimeStamp) ERROR: Could not write to log file: $_"
            return
        }
    }
}
