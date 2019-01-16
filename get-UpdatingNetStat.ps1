<#
        .Notes  
            File Name      : get-UpdatingNetStat.ps1
            Version        : v.1.0
            Author         : @TerrySmithMBA
            Prerequisite   : Windows PowerShell 5.0
            Created        : January 16, 2019
            Info           : Creates a live netstat to monitor new established connections.
#>

Write-Host "Monitoring Connections"

while ($true){
    $current = get-nettcpconnection | ? {$_.state -eq "established"} | out-string
    sleep(1)
    $compare = get-nettcpconnection | ? {$_.state -eq "established"} | out-string
    if ($compare){
        $update = compare-object ($compare) ($current)
        if ($update -ne $null){
            clear
            $compare
        }
        $compare = $current
        sleep(1)
    }
    else {
        $compare = $current
    }
}
