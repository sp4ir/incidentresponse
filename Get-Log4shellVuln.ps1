<# 
    .SYNOPSIS
    Get-Log4shellVuln.ps1 scans all local drives for presence of log4j jar files and analyzes the contents of the jar file to determine if it is vulnerable to #log4shell (CVE-2021-44228) vulnerability
    .DESCRIPTION
    Review all local disks for any presence of log4j jar files, extract the manifest from the file and determine if the version is less than 2.15.
    Output to console status of individual files and global result at end.
    Record list of all jar files in log4j.csv, manifest versions in log4j-manifest.csv, and finally presence of jndi class in log4j-jndi.csv
    Requires .net 4 or later
    Use Update-Log4shellVuln.ps1 to mitigate the vulnerability by deleting the JndiLookup.class from within the vulnerable JAR files. (Note: Industry recommendation is to upgrade, but this may be a good temporary stop-gap)

    Output files:
    "C:\log4j-result.txt" #Final result of script, 'Not Vulnerable' or 'Vulnerable'
    "C:\log4j-vuln.csv" #List of only vulnerable log4*.jar files    
    "C:\log4j.csv" # List of all log4j*.jar files    
    "C:\log4j-manifest.csv" #List of all log4j*.jar files and their manifest version
    "C:\log4j-vuln.csv" #List of only vulnerable log4*.jar files
    "C:\log4j-vuln16.csv" #List of 2.16 log4*.jar files which are not-vulnerable to RCE CVE-2021-44228 but remain vulnerable to CVE-2021-45105 
    "C:\log4j-jndi.csv" #List of JndiLookup.class files within jar files
#>
param (
    #Specifies a folder to store resultant CSV and TXT files for later analysis. Defaults to C:\
    [Parameter(Mandatory = $false)]
    [string]
    $logFolder = "C:\"
)
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$resultFile = "$logFolder\log4j-result.txt" # Final result of script, 'Not Vulnerable' or 'Vulnerable'
$log4jCsv = "$logFolder\log4j.csv" # List of all log4j*.jar files
$targetManifestFile = "$logFolder\log4j-manifest.txt" # Temporary file for extracting manifest meta information from a text file
$manifestCsv = "$logFolder\log4j-manifest.csv" #List of all log4j*.jar files and their manifest version
$vulnerableCsv = "$logFolder\log4j-vuln.csv" #List of only vulnerable log4*.jar files
$vulnerable16Csv = "$logFolder\log4j-vuln16.csv" #List of 2.16 log4*.jar files which are not-vulnerable to RCE CVE-2021-44228 but remain vulnerable to CVE-2021-45105 
$jndiCsv = "$logFolder\log4j-jndi.csv" #List of JndiLookup.class files within jar files
$log4Filter = "log4j*.jar"
Remove-Item $vulnerableCsv -Force -ErrorAction SilentlyContinue
$jarFiles = Get-PSDrive | Where-Object { $_.Name.length -eq 1 } | Select-Object -ExpandProperty Root | Get-ChildItem -File -Recurse -Filter $log4Filter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
####$jarFiles = Get-ChildItem $logFolder -File -Recurse -Filter $log4Filter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
if ($jarFiles) { $jarFiles | Out-File $log4jCsv }
$global:result = $null
foreach ($jarFile in $jarFiles) {
    Write-Output "$($jarFile.ToString())"
    $global:jndiExists = $false
    $zip = [System.IO.Compression.ZipFile]::OpenRead($jarFile)
    $zip.Entries | Where-Object { $_.Name -like 'JndiLookup.class' } | ForEach-Object {
        $output = "$($jarFile.ToString()),$($_.FullName)"
        Write-Output $output
        $output | Out-File -Append $jndiCsv
        if ($null -eq $global:result) { $global:result = "Jndi class exists" }
        $global:jndiExists = $true
    }
    $zip.Entries | Where-Object { $_.FullName -eq 'META-INF/MANIFEST.MF' } | ForEach-Object {
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $targetManifestFile, $true)
        $implementationVersion = (Get-Content $targetManifestFile | Where-Object { $_ -like 'Implementation-Version: *' }).ToString()
        Write-Output $implementationVersion
        "$($jarFile.ToString()),$($implementationVersion.ToString())" | Out-File -Append $manifestCsv
        Remove-Item $targetManifestFile -ErrorAction SilentlyContinue
        $implementationVersion_ = $implementationVersion.Replace('Implementation-Version: ', '').Split('.')
        if ([int]$implementationVersion_[0] -eq 2 -and [int]$implementationVersion_[1] -le 15 ) {
            Write-Output "log4shell vulnerable version"
            if ($global:jndiExists) {
                "$($jarFile.ToString())" | Out-File -Append $vulnerableCsv
                $global:result = "Vulnerable"
            }
        }
        elseif ([int]$implementationVersion_[0] -eq 2 -and [int]$implementationVersion_[1] -eq 16 ) {
            Write-Output "2.16 is not vulnerable to log4shell (CVE-2021-44228) but is vulnerable to DoS vulnerability CVE-2021-45105"
            "$($jarFile.ToString())" | Out-File -Append $vulnerable16Csv
        }
    }
}
if ($null -eq $global:result) { $global:result = "Not Vulnerable" }
$global:result | Out-File $resultFile
Write-Output "$global:result"
