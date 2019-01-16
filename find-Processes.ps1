    <#
        .USAGE
            
            find-Processes.ps1 | export-csv c:\users\foo\bar.csv
    
        
        .Notes  

            File Name      : find-Processes.ps1
            Version        : v.3.0
            Author         : @TerrySmithMBA, @Playstation1
            Prerequisite   : Windows PowerShell 5.0
            Created        : January 16, 2019
    

        .Additional_Info
            
            Tuning the script:
                To reduce false positives (tune the script to your environment), enter known processes in your environment into the lisaProcesses string.
                (1) Ensure that the process is spelled correctly, (2) divide the process name, path, and parent process by pound signs (hashtags), (3) ensure your entry doesn't share the same line as a different entry.

                Example:
                    If you were adding knowngood.exe to lisaProcesses, the last two lines would look as follows
                        splunk-winevtlog##
                        knowngood#c:\windows\system32\knowngood.exe#knowngoodparent.exe

                    If path and/or parent process is not known
                        splunk-winevtlog##
                        knowngood##
    #>


    function getProcessesThatStandOut(){

    #Lisa processes come from a clean Windows 10. The name Lisa is the name of my clean Windows 10 image.

    #IMPORTANT: To reduce false positives (tune the script to your environment), enter known processes in your environment into the lisaProcesses string.
        #(1) Ensure that the process is spelled correctly, (2) divide the process name, path, and parent process by pound signs (hashtags), (3) ensure your entry doesn't share the same line as a different entry.

    $lisaProcesses = "csrss##
    csrss##
    dwm#C:\Windows\system32\dwm.exe#winlogon.exe
    explorer#C:\Windows\Explorer.EXE#
    fontdrvhost#C:\Windows\system32\fontdrvhost.exe#winlogon.exe
    Idle##
    iexplore#C:\Program Files\Internet Explorer\iexplore.exe#
    iexplore#C:\Program Files (x86)\Internet Explorer\IEXPLORE.EXE#
    lsass#C:\Windows\system32\lsass.exe#wininit.exe
    MpCmdRun#C:\Program Files\Windows Defender\MpCmdRun.exe#
    msdtc#C:\Windows\System32\msdtc.exe#services.exe
    MsMpEng##services.exe
    RuntimeBroker#C:\Windows\System32\RuntimeBroker.exe#svchost.exe
    SearchUI#C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe#svchost.exe
    services##wininit.exe
    ShellExperienceHost#C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe#svchost.exe
    sihost#C:\Windows\system32\sihost.exe#svchost.exe
    smss##System
    spoolsv#C:\Windows\System32\spoolsv.exe#services.exe
    svchost#C:\Windows\system32\svchost.exe#
    svchost#C:\Windows\system32\svchost.exe#
    svchost#C:\Windows\system32\svchost.exe#
    svchost#C:\Windows\system32\svchost.exe#
    svchost#C:\Windows\system32\svchost.exe#
    svchost#C:\Windows\System32\svchost.exe#
    svchost#C:\Windows\System32\svchost.exe#
    svchost#C:\Windows\system32\svchost.exe#
    svchost#C:\Windows\system32\svchost.exe#
    svchost#C:\Windows\System32\svchost.exe#
    svchost#C:\Windows\System32\svchost.exe#
    svchost#C:\Windows\system32\svchost.exe#
    svchost#C:\Windows\system32\svchost.exe#
    System##
    taskhostw#C:\Windows\system32\taskhostw.exe#svchost.exe
    wininit#
    winlogon#C:\Windows\system32\winlogon.exe#
    wlms#C:\Windows\system32\wlms\wlms.exe#services.exe
    WmiPrvSE#C:\Windows\system32\wbem\wmiprvse.exe#svchost.exe
    wsmprovhost#C:\Windows\system32\wsmprovhost.exe#svchost.exe
    ac.activclient.gui.scagent##
    ACCM_MSGBUS##
    ACCM_WATCH##
    acevents##
    acrotray##
    AGMService##
    AGSService##
    aiCOMMAPI##
    ApplicationFrameHost##
    armsvc##
    AuditManagerService##
    CcmExec##
    CmRcService##
    ctfmon##
    dllhost##
    DVService##
    DVTrayApp##
    fcags##
    fcag##
    FireSvc##
    HipMgmt##
    igfxCUIService##
    igfxEM##
    igfxHK##
    igfxTray##
    InstallRootService##
    macmnsvc##
    macompatsvc##
    masvc##
    mcshield##
    mctray##
    Memory Compression##
    mfeann##
    mfefire##
    mfehcs##
    mfemactl##
    mfemms##
    mfevtps##
    mfevtps##
    mobsync##
    MSASCuiL##
    NetBanner##
    policyHost##
    PresentationFontCache##
    SCNotification##
    SearchIndexer##
    SecurityHealthService##
    smartscreen##
    splunkd##
    splunk-winevtlog##"

    $lisaProcesses = $lisaProcesses.Trim()

        foreach($proc in get-process){
            $name = $proc.Name
            $path = $proc.Path
            $parentprocessid = (get-wmiobject win32_process | ? {$_.name -eq "$name`.exe"}).parentprocessid
            $parentprocess = (get-wmiobject win32_process | ? {$_.processid -eq $parentprocessid}).name
        
            if (($lisaProcesses | %{$_ -match $name}) -contains $true) {
                foreach ($line in $lisaProcesses -split "`n"){
                $line = $line.trim()
                    if ($line -like "$name`#*"){
                        $correctlocation = $line.split("#")[1]
            
                        if ($line.split("#")[1]){
            
                            if ($path -ne $line.split("#")[1] -and $name -ne "iexplore" -and $path){
                                get-wmiobject win32_process | ? {$_.processid -eq $proc.id} | select name, @{n="issue";e={"Process running from wrong location"}}, @{n="moreInfo";e={"Correct Location: $correctlocation; Actual Location: $path"}}
                            }

                            elseif ($name -eq "iexplore" -and (Get-CimInstance Win32_OperatingSystem).caption -like "*server*"){
                                get-wmiobject win32_process | ? {$_.processid -eq $proc.id} | select name, @{n="issue";e={"Internet Explorer running on Windows Server"}}
                            }
                        }
                    
                    }
                }
            }


            else {
                   if ($name -ne "browser_broker" -and $name -ne "conhost" -and $name -ne "dasHost" -and $name -ne "HxAccounts" -and $name -ne "HxOutlook" -and $name -ne "HxTsr" -and
                    $name -ne "MicrosoftEdge" -and $name -ne "MicrosoftEdgeCP" -and $name -ne "mshta" -and $name -ne "OfficeHubTaskHost" -and $name -ne "sedsvc" -and $name -ne "SkypeApp" -and
                    $name -ne "SkypeBackgroundHost" -and $name -ne "SystemSettings" -and $name -ne "Windows.WARP.JITService" -and $name -ne "wsmprovhost" -and $name -ne "microsoft.photos" -and $name -ne "cmd"){

                        if ($proc.company){
                            $company = $proc.company
                        }
                        else {
                            $company = "No Company Information Given"
                        }

                        if ($proc.starttime){
                            $starttime = $proc.starttime
                        }
                        else {
                            $starttime = "No start time given"
                        }
                        get-wmiobject win32_process | ? {$_.processid -eq $proc.id} | select name, @{n="issue";e={"Additional Process Running"}}, @{n="moreInfo";e={"Start Time: $starttime`; Company: $company"}}
                   }
            }
        }
    }



    getProcessesThatStandOut
