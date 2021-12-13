<# Update-Log4shellVuln.ps1
    .SYNOPSIS
    Update-Log4shellVuln.ps1 for #log4shell vulnerablility (CVE-2021-44228) takes output from .\Get-Log4shellVuln.ps1 and processes each JAR file and attempts to remove the JndiLookup.class file from the archive to mitigate the vulnerability.
    .DESCRIPTION
    Process specifically specified JAR files from a txt file and remove any instance of JndiLookup.class
#>
param (
    [Parameter(Mandatory = $false)]
    [string]
    $logFolder = "C:\"
)
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$vulnerableCsv = "$logFolder\log4j-vuln.csv"
$mitigationResultFile = "$logFolder\log4j-fix.txt"
$JndiLookupCount = 0
$jarFiles = Import-Csv $vulnerableCsv -Header "Name"
foreach ($jarFile in $jarFiles) {
    Write-Output $jarFile    
    $stream = New-Object IO.FileStream($jarFile.Name, [IO.FileMode]::Open)
    $zip = New-Object IO.Compression.ZipArchive($stream, [IO.Compression.ZipArchiveMode]::Update)
    ($zip.Entries | Where-Object { $_.Name -eq 'JndiLookup.class' }) | ForEach-Object { 
        Write-Output "Deleting $($_.FullName)"
        $_.Delete()
    }
    $JndiLookupCount += $(($zip.Entries | Where-Object { $_.Name -eq 'JndiLookup.class' }).Count)
    $zip.Dispose()
    $stream.Close()
    $stream.Dispose()
}
"$JndiLookupCount" | Out-File $mitigationResultFile
Write-Output "JndiLookup files end state: $JndiLookupCount" 
