$lisaTasksAndPaths = gc "C:\Users\abcd\Downloads\BlueTeamPowershellScripts-master (1)\BlueTeamPowershellScripts-master\get-ScheduledTasksThatStandOut\lisa_schtasks.txt"

Write-Host "Checking scheduled tasks..."

foreach($task in get-scheduledtask){

    $name = $task.taskname
    $path = $task.taskpath
    $state = $task.state

    if (($lisaTasksAndPaths | %{$_ -match $name}) -contains $true) {
        foreach ($line in $lisaTasksAndPaths){
            if ($line -like "$name`#*"){
                $correctpath = $line.split("#")[1]
                

                if ($line.split("#")[1]){
                    if ($path -ne $line.split("#")[1] -and $line -notlike "OneDrive*" -and $line -notlike "User_Feed*"){
                        Write-Host "Scheduled Task: $name" -ForegroundColor Red
                        Write-Host "Correct path: $correctpath `nActual path: $path" -ForegroundColor Red
                        Write-Host Wrong path for $name -ForegroundColor Red
                        Write-Host "`n"
                    }
                }
                break
            }       
        }
    }

    elseif ($line -like "OneDrive*" -and $line -like "User_Feed*"){
        continue;
    }
    else {
        Write-Host "Additional Task: $name" -Foregroundcolor Yellow
        Write-Host "Path: $path" -Foregroundcolor Yellow
        Write-Host "`n"

    }    

}

    



