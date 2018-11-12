<#
.SYNOPSIS
    Outputs the following:
        1. Process Name
        2. Path based on Get-Database.ps1 script [Should be a from a master image]
        3. Actual Location of Process
        4. If locations do not match, a notification appears next.
        5. Name of Parent Process
        
.EXAMPLE
    Process: svchost
    Correct Location: c:\windows\system32\svchost.exe 
    Actual Location: c:\users\badguy\downloads\svchost.exe
    svchost in wrong location!
    Parent Process: bad.exe

.USAGE
    crystalblue.ps1



#>


    $locations = gc "lisa image.txt"
    Write-Host "Checking processes..."
    foreach($proc in get-process){
        $name = $proc.Name
        $path = $proc.Path
    
        $parentprocessid = (get-wmiobject win32_process | ? {$_.name -eq "$name`.exe"}).parentprocessid
        $parentprocess = (get-wmiobject win32_process | ? {$_.processid -eq $parentprocessid}).name
        
        if (($locations | %{$_ -match $name}) -contains $true) {

            foreach ($line in $locations){
            if ($line -like "$name`#*"){

                $correctlocation = $line.split("#")[1]
                Write-Host "Process: $name" 
                if ($line.split("#")[1]){
                    Write-Host "Correct Location: $correctlocation `nActual Location: $path"
                    if ($path -ne $line.split("#")[1]){
                        Write-Host $name in wrong location!
                    }
                }
                else {
                    Write-Host "No path information given"
                }

                if ($parentprocess){
                    Write-Host "Parent Process: $parentprocess`n`n`n`n`n"
                }
                else {
                    Write-Host "No Parent Process`n`n`n`n`n"
                }
                break
                }
       
            }
        }
        else {
            $company = $proc.company
            $starttime = $proc.starttime
            Write-Host "Additional Process Running: $name"
            Write-Host "Start time: $starttime"
            if ($company){
                Write-Host "Company: $company"
            }
            else {
                Write-Host "No company information given"

            }
            Write-Host "`n"
        }
        
    }

