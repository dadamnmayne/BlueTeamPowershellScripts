
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
