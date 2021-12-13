<#
    .SYNOPSIS
    Get-Log4shellVuln.ps1 scans all local drives for presence of log4j jar files and analyzes the contents of the jar file to determine if it is vulnerable to #log4shell (CVE-2021-44228) vulnerability
    .DESCRIPTION
    Review all local disks for any presence of log4j jar files, extract the manifest from the file and determine if the version is less than 2.15.
    Output to console status of individual files and global result at end.
    Record list of all jar files in log4j.csv, manifest versions in log4j-manifest.csv, and finally presence of jndi class in log4j-jndi.csv
    Requires .net 4 or later
#>
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$logFolder = "C:\"
$log4jCsv = "$logFolder\log4j.csv"
$targetManifestFile = "$logFolder\log4j-manifest.txt"
$manifestCsv = "$logFolder\log4j-manifest.csv"
$jndiCsv = "$logFolder\log4j-jndi.csv"
$log4Filter = "log4j*.jar"
$jarFiles = Get-PSDrive | Where-Object { $_.Name.length -eq 1 } | Select-Object -ExpandProperty Root | Get-ChildItem -File -Recurse -Filter $log4Filter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
if ($jarFiles){$jarFiles | Out-File $log4jCsv}
$global:result = $null
foreach ($jarFile in $jarFiles) {
    Write-Output $jarFile
    $zip = [System.IO.Compression.ZipFile]::OpenRead($jarFile)
    $zip.Entries | 
    Where-Object { $_.Name -like 'JndiLookup.class' } | ForEach-Object {  
        $output = "$($jarFile.ToString()),$($_.FullName)"      
        Write-Output $output
        $output | Out-File -Append $jndiCsv        
        if ($null -eq $global:result) { $global:result = "Jndi class exists" }        
    }
    $zip.Entries | 
    Where-Object { $_.FullName -eq 'META-INF/MANIFEST.MF' } | ForEach-Object {        
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, $targetManifestFile, $true)
        $implementationVersion = (Get-Content $targetManifestFile | Where-Object { $_ -like 'Implementation-Version: *' }).ToString()
        Write-Output $implementationVersion
        "$($jarFile.ToString()),$($implementationVersion.ToString())" | Out-File -Append $manifestCsv   
        Remove-Item $targetManifestFile -ErrorAction SilentlyContinue
        $implementationVersion_ = $implementationVersion.Replace('Implementation-Version: ', '').Split('.')
        if ($implementationVersion_[0] -eq 2 -and $implementationVersion_ -lt 15 ) {
            Write-Output "log4shell vulnerability exists"
            $global:result = "Vulnerable"
        }
    }
    if ($null -eq $global:result) { $global:result = "Jndi class not found" }
}
Write-Output "Result: $global:result"
