    param (
        [string]$computername
    )

invoke-command $computername {Get-ChildItem -path C:\Windows\Prefetch | sort-object lastaccesstime | format-table lastaccesstime,name} >> ${computername}report.txt                                                                                                                                   
invoke-command $computername {netstat -anob} >> ${computername}report.txt                                                            
invoke-command $computername {net share} >> ${computername}report.txt                                                                                                                                  
invoke-command $computername {net use} >> ${computername}report.txt                                                                  
invoke-command $computername {netstat -r} >> ${computername}report.txt                                                                                                                               
invoke-command $computername {ipconfig /all|findstr DNS} >> ${computername}report.txt                                                                                                                                                  
invoke-command $computername {get-content c:\windows\system32\drivers\etc\hosts}                                          
invoke-command $computername {get-content c:\windows\system32\drivers\etc\hosts} >> ${computername}report.txt                        
invoke-command $computername {tasklist} >> ${computername}report.txt                                                                 
invoke-command $computername {Get-Service} >> ${computername}report.txt                                                              
invoke-command $computername {net user} >> ${computername}report.txt                                                                 
invoke-command $computername {wmic product list full} >> ${computername}report.txt                                                   
invoke-command $computername {reg query hkey_current_user\software\microsoft\windows\currentversion\run} >> ${computername}report.txt
invoke-command $computername {reg query hkey_local_machine\software\microsoft\windows\currentversion\run} >> ${computername}report.txt
invoke-command $computername {reg query hkey_local_machine\software\microsoft\windows\currentversion\runonce} >> ${computername}report.txt
invoke-command $computername {wmic startup list full} >> ${computername}report.txt                                                   
invoke-command $computername {schtasks} >> ${computername}report.txt
Invoke-Command -ComputerName $computername {get-childitem C:\ -recurse -force | where {$_.extension -eq ".dll"} | get-filehash -Algorithm md5 | format-list path, hash} >> ${computername}report.txt
invoke-command $computername {get-childitem C:\ -recurse | where {$_.extension -eq ".ps1"}} >> ${computername}report.txt                                                          
invoke-Command $computername {get-childitem C:\ -recurse -force | where {$_.extension -eq ".exe"} | get-filehash -Algorithm md5 | format-list path, hash} >> ${computername}report.txt                                                        
Invoke-Command $computername {foreach ($proc in get-process) {Get-FileHash $proc.path -Algorithm md5 -ErrorAction stop}}>> ${computername}report.txt
invoke-command $computername {get-eventlog application -newest 10000} > ${computername}applogs.txt
invoke-command $computername {get-eventlog system -newest 100000} > ${computername}systemlogs.txt
invoke-command $computername {get-eventlog security -newest 100000} > ${computername}securitylogs.txt
