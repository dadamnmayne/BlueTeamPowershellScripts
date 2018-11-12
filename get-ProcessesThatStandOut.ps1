<#
.SYNOPSIS
    Outputs the following:
        1. Process Name
        2. Path based on Get-Database.ps1 script [Should be a from a master image]
        3. Actual Location of Process
        4. If locations do not match, a notification appears next.
        5. Name of Parent Process
        
    If the process stands out in any way [basically meaning that the process wouldn't be running on a clean and brand new Windows image],
    the following will appear
        1. Addition Process Running: [process]
        2. Start time
        3. Any company information about the file.
        
        
        
.EXAMPLE

    Process: svchost
    Correct Location: c:\windows\system32\svchost.exe 
    Actual Location: c:\users\badguy\downloads\svchost.exe
    svchost in wrong location!
    Parent Process: bad.exe
    
    Additional Process Running: Windows.WARP.JITService
    Start time: 11/09/2018 16:13:59
    No company information given


    Additional Process Running: Windows.WARP.JITService
    Start time: 11/09/2018 16:23:03
    No company information given


    Additional Process Running: Windows.WARP.JITService
    Start time: 11/09/2018 16:14:08
    No company information given


    Additional Process Running: WinStore.App
    Start time: 11/09/2018 14:56:56
    Company: Microsoft Corporation


    Additional Process Running: WinStore.App
    Start time: 11/09/2018 14:56:56
    Company: Microsoft Corporation
    
    
    Analysts are reminded that all of this information can be faked and/or obfuscated.
    
    

.USAGE
    crystalblue.ps1



#>

    #lisa image.txt is a baseline of all running processes after installing Windows.
    #replace if necessary.
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

