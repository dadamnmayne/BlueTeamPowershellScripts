

function menu(){
    while($true){
        Write-Host "1. Get Operating System Information"
        Write-Host "2. Hunt Evil/Find Misconfigurations"
        Write-Host "3. Watch for Evil/Misconfigurations"
        Write-Host "4. Get Forensic Info (Accessed Executables, DNS Cache...)"
        Write-Host "5. Options"
        $choice = Read-Host

        switch($choice){
            "1" {
                clear
                getMachineAndOSInfo
            }
            "2"{ 
                clear
                getInterrogation
                ps1
                sleep(1)
                
            }
            "3"{
        
            }
            "4"{
                clear
                getForensicInfo
            }
            "5"{
            
            }
        }

    }
}

function getMachineAndOSInfo(){
    Write-Host "Operating System Information" -ForegroundColor Green
    get-ciminstance Win32_OperatingSystem | select-object Caption, Version, InstallDate, ServicePackMajorVersion, OSArchitecture, BootDevice, csname, NumberOfUsers, LastBootUpTime, NumberOfProcesses | fl
    
    Write-Host "OS Updates [Hotfixes]" -ForegroundColor Green
    get-hotfix | out-string

    Write-Host "Network Information" -ForegroundColor Green
    #Get IP Config
    get-netipconfiguration | out-string

    Write-Host "User Accounts" -ForegroundColor Green
    #User accounts and current login information
    get-localuser | ft name, enabled, passwordrequired, lastlogon

    Write-Host "Current Logins" -ForegroundColor Green
    Write-Host "`n"
    ((query user | out-string) -split "`n").trim()
    Write-Host "`n`n"

    #Check installed Applications
    if (get-wmiobject -class win32_product){
        Write-Host "Installed Applications" -ForegroundColor Green
        get-wmiobject -class win32_product
    }
    else {
        Write-Host "No Installed Applications`n`n" -ForegroundColor Yellow
    }

    Write-Host "Shares and Mapped Drives" -ForegroundColor Green
    #Shares and Mapped Drives
    get-wmiobject -class win32_share | out-string
    get-wmiobject -class win32_mappedlogicaldisk | out-string
    
    Write-Host "`n`n`n"

    $menu = Read-Host "Press any key to return to the main menu"
    clear
}

function getInterrogation(){

    #Startup/Autorun applications
    function getStartupAutorunItems(){
        clear
        Write-Host "Checking for persistence items...`n" -Foregroundcolor Green
        if ((get-childitem -force 'HKLM:\software\microsoft\' | ? {$_.property -eq "Autorun"}))  {
            Write-Host "HKLM:\Software\Microsoft contain Autoruns" -ForegroundColor Yellow
            Write-Host "`n`t" ((gci -force 'HKLM:\SOFTWARE\Microsoft' | out-string) -split "`n" | select-string Autorun | out-string).replace("Autorun            :","").trim() -ForegroundColor Yellow
            Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
            Write-Host "`t`t- Could be used so that malware can persist." -ForegroundColor Gray
            Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
            Write-Host "`n`n`n"
            }

        if ((Get-Item 'HKLM:\software\microsoft\windows\CurrentVersion\run').ValueCount -gt 1){
            Write-Host "Additional Keys in Windows\CurrentVersion\Run" -ForegroundColor Yellow
            $x = ((Get-Item 'HKLM:\software\microsoft\windows\CurrentVersion\run' | out-string) -split "`n").length
            Write-Host "`n`t" (((Get-Item 'HKLM:\software\microsoft\windows\CurrentVersion\run' | out-string) -split "`n")[8..$x] | out-string).trim() -ForegroundColor Yellow
            Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
            Write-Host "`t`t- Could be used so that malware can persist." -ForegroundColor Gray
            Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
            Write-Host "`n`n`n"
        }

        if ((get-childitem -force 'c:\programdata\microsoft\windows\start menu\programs\startup').count -gt 1){
            Write-Host "Additional Items in C:\ProgramData\Microsoft\Windows\Start Menu\programs\startup" -ForegroundColor Yellow
            Write-Host "`n`t" (get-childitem -force 'c:\programdata\microsoft\windows\start menu\programs\startup' | ?{$_.name -ne 'desktop.ini'}).name -ForegroundColor Yellow
            Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
            Write-Host "`t`t- Could be used so that malware can persist." -ForegroundColor Gray
            Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
            Write-Host "`n`n`n"
        }

        if ((gci $PSHome | ? {$_.name -like "*profile.ps1"}) ){
            Write-Host "$PSHOME\Profile.ps1 has been changed." -ForegroundColor Yellow   
            Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
            Write-Host "`t`t- This file can be used to execute malware when Powershell.exe is executed." -ForegroundColor Gray
            Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
            Write-Host "`n`t`t`t`t`t Check $PSHOME\Profile.ps1." -ForegroundColor Gray
            Write-Host "`n`n`n"
        }

        if ( (($env:path | out-string).split(";")).count -gt 6){          
            Write-Host "The Path environmental variable has been changed." -ForegroundColor Yellow
            Write-Host "`n`tDefault Path for Windows: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Users\icebo\AppData\Local\Microsoft\WindowsApps`n" -ForegroundColor Yellow
            Write-Host "`tPath for this system: $env:path" -ForegroundColor Yellow
            Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
            Write-Host "`t`t- Attackers can take advantage of local defenders by redirecting commands to perform a malicious action" -ForegroundColor Gray
            Write-Host "`t`tbefore a legitimate command." -ForegroundColor Gray
            Write-Host "`n`t`t`tExample: `n`t`t`t1. User opens CMD.EXE and types `"tasklist`"" -ForegroundColor Gray
            Write-Host "`t`t`t2. `"Tasklist`" actually calls a script that runs a malicious command first, then runs" -ForegroundColor Gray
            Write-Host "`t`t`tthe real tasklist so that everything seems normal`n" -ForegroundColor Gray
            Write-Host "`t`t`t`t Course of Action:" -ForegroundColor Gray
            Write-Host "`t`t`t`t`t - Investigate any additional folders in the path.`n`n`n" -ForegroundColor Gray
        }

        if (((get-item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' | out-string) -split "`n" | select-string Userinit | out-string).replace("Userinit                     :","").trim() -ne "C:\Windows\system32\userinit.exe,"){
            Write-Host "Potential Threat found in the UserInit Registry value." -ForegroundColor Yellow
            Write-Host "`n`tDefault USERINIT value for Windows: C:\Windows\system32\userinit.exe" -ForegroundColor Yellow
            Write-Host "`tActual USERINIT value:"((get-item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' | out-string) -split "`n" | select-string Userinit | out-string).replace("Userinit                     :","").trim() -ForegroundColor Yellow
            Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
            Write-Host "`t`t- Artifacts in this value automatically run. Could be used to persist." -ForegroundColor Gray
            Write-Host "`n`t`t`t Course of Action:" -ForegroundColor Gray
            Write-Host "`t`t`t`t - Make sure only userinit.exe is in this value.`n`n`n" -ForegroundColor Gray
        }
        Write-Host "`n"
    }
    getStartupAutorunItems

    #Process Related Information
    function getProcessesThatStandOut(){
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
    wsmprovhost#C:\Windows\system32\wsmprovhost.exe#svchost.exe"

    $lisaProcesses = $lisaProcesses.Trim()

        Write-Host "Checking processes...`n" -ForegroundColor Green
        [bool]$noUnknownProcesses = $true

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
            
                        if ($path -ne $line.split("#")[1] -and $name -ne "iexplore"){
                            Write-Host "Process running from wrong location!" -ForegroundColor Yellow
                            Write-Host "Process: $name" -ForegroundColor Yellow
                            Write-Host "Correct Location: $correctlocation `nActual Location: $path" -ForegroundColor Yellow
                            Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
                            Write-Host "`n`tTrojans typically mimic legitimate processes by name but run from incorrect locations." -ForegroundColor Gray
                            Write-Host "`t`t- Malicious running processes are used as means of persistence and should be killed/removed." -ForegroundColor Gray
                            Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
                            Write-Host "`n`t`t`t`t`t Ensure that this process does not belong to legitimate applications or the Windows environment." -ForegroundColor Gray
                            Write-Host "`n`t`t`t`t`t Remove process immediately if this process is not being used legitimately." -ForegroundColor Gray
                            Write-Host "`n`n`n"
                            $noUnknownProcesses = $false
                        }
                        elseif ($name -eq "iexplore"){
                            Write-Host "Internet Explorer running on Windows Server" -ForegroundColor Yellow
                            Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
                            Write-Host "`n`tAdministrators should not use Internet Explorer on servers as this increases the attack surface." -ForegroundColor Gray
                            Write-Host "`t`t- If absolutely necessary, administrators must use great caution." -ForegroundColor Gray
                            Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
                            Write-Host "`n`t`t`t`t`t Find out whats going on. Ensure that this is legitimate and absolutely necessary." -ForegroundColor Gray
                            Write-Host "`n`t`t`t`t`t Remove process immediately if not being used legitimately." -ForegroundColor Gray
                            Write-Host "`n`n`n"
                            
                        }
                    }
                    else {
                    
                    }
                    <#
                    if ($parentprocess){
                        Write-Host "Parent Process: $parentprocess`n`n`n`n`n"
                    }
                    else {
                        Write-Host "No Parent Process`n`n`n`n`n"
                    } #>
                    break
                    }
       
                }
            }


            else {
                if ($name -ne "browser_broker" -and $name -ne "conhost" -and $name -ne "dasHost" -and $name -ne "HxAccounts" -and $name -ne "HxOutlook" -and $name -ne "HxTsr" -and
                    $name -ne "MicrosoftEdge" -and $name -ne "MicrosoftEdgeCP" -and $name -ne "mshta" -and $name -ne "OfficeHubTaskHost" -and $name -ne "sedsvc" -and $name -ne "SkypeApp" -and
                    $name -ne "SkypeBackgroundHost" -and $name -ne "SystemSettings" -and $name -ne "Windows.WARP.JITService" -and $name -ne "wsmprovhost" -and $name -ne "microsoft.photos" -and $name -ne "cmd"){
                    $company = $proc.company
                    $starttime = $proc.starttime
                    $noUnknownProcesses = $false
                    Write-Host "Additional Process Running: $name" -ForegroundColor Yellow
                    Write-Host "Start time: $starttime"
                    if ($company){
                        Write-Host "Company: $company"
                    }
                    else {
                        Write-Host "No company information given"
                    }

                    Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
                    Write-Host "`t`t- Malicious running processes are used as means of persistence and should be killed/removed." -ForegroundColor Gray
                    Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
                    Write-Host "`n`t`t`t`t`t Ensure that this process does not belong to legitimate applications or the Windows environment." -ForegroundColor Gray
                    Write-Host "`n`t`t`t`t`t Remove process immediately if this process is not being used legitimately." -ForegroundColor Gray
                    Write-Host "`n`n`n"
                }
            }
        
        }
    if ($noUnknownProcesses){
        Write-Host "***NO UNKNOWN PROCESSES***" -ForegroundColor Green
    }
    }
    getProcessesThatStandOut

    #Services Related Information
    function getServicesThatStandOut{
    #FUNCTION NOT TESTED
        $lisaServices = 'AJRouter#AllJoyn Router Service#Stopped#Manual
    ALG#Application Layer Gateway Service#Stopped#Manual
    AppIDSvc#Application Identity#Stopped#Manual
    Appinfo#Application Information#Running#Manual
    AppMgmt#Application Management#Stopped#Manual
    AppReadiness#App Readiness#Stopped#Manual
    AppVClient#Microsoft App-V Client#Stopped#Disabled
    AppXSvc#AppX Deployment Service (AppXSVC)#Stopped#Manual
    AudioEndpointBuilder#Windows Audio Endpoint Builder#Stopped#Manual
    Audiosrv#Windows Audio#Stopped#Manual
    AxInstSV#ActiveX Installer (AxInstSV)#Stopped#Manual
    BFE#Base Filtering Engine#Running#Automatic
    BITS#Background Intelligent Transfer Service#Stopped#Manual
    BrokerInfrastructure#Background Tasks Infrastructure Service#Running#Automatic
    Browser#Computer Browser#Stopped#Disabled
    bthserv#Bluetooth Support Service#Stopped#Manual
    CDPSvc#Connected Devices Platform Service#Running#Automatic
    CDPUserSvc_20d8a#CDPUserSvc_20d8a#Running#Automatic
    CertPropSvc#Certificate Propagation#Stopped#Manual
    ClipSVC#Client License Service (ClipSVC)#Stopped#Manual
    COMSysApp#COM+ System Application#Stopped#Manual
    CoreMessagingRegistrar#CoreMessaging#Running#Automatic
    CryptSvc#Cryptographic Services#Running#Automatic
    CscService#Offline Files#Stopped#Disabled
    DcomLaunch#DCOM Server Process Launcher#Running#Automatic
    DcpSvc#DataCollectionPublishingService#Stopped#Manual
    defragsvc#Optimize drives#Stopped#Manual
    DeviceAssociationService#Device Association Service#Stopped#Manual
    DeviceInstall#Device Install Service#Stopped#Manual
    DevQueryBroker#DevQuery Background Discovery Broker#Stopped#Manual
    Dhcp#DHCP Client#Running#Automatic
    diagnosticshub.standardcollector.service#Microsoft (R) Diagnostics Hub Standard Collector Service#Stopped#Manual
    DiagTrack#Connected User Experiences and Telemetry#Running#Automatic
    DmEnrollmentSvc#Device Management Enrollment Service#Stopped#Manual
    dmwappushservice#dmwappushsvc#Stopped#Manual
    Dnscache#DNS Client#Running#Automatic
    dot3svc#Wired AutoConfig#Stopped#Manual
    DPS#Diagnostic Policy Service#Running#Automatic
    DsmSvc#Device Setup Manager#Stopped#Manual
    DsSvc#Data Sharing Service#Stopped#Manual
    Eaphost#Extensible Authentication Protocol#Stopped#Manual
    EFS#Encrypting File System (EFS)#Stopped#Manual
    embeddedmode#Embedded Mode#Stopped#Manual
    EntAppSvc#Enterprise App Management Service#Stopped#Manual
    EventLog#Windows Event Log#Running#Automatic
    EventSystem#COM+ Event System#Running#Automatic
    fdPHost#Function Discovery Provider Host#Stopped#Manual
    FDResPub#Function Discovery Resource Publication#Stopped#Manual
    FontCache#Windows Font Cache Service#Running#Automatic
    FrameServer#Windows Camera Frame Server#Stopped#Manual
    gpsvc#Group Policy Client#Running#Automatic
    hidserv#Human Interface Device Service#Stopped#Manual
    HvHost#HV Host Service#Stopped#Manual
    icssvc#Windows Mobile Hotspot Service#Stopped#Manual
    IKEEXT#IKE and AuthIP IPsec Keying Modules#Stopped#Manual
    iphlpsvc#IP Helper#Running#Automatic
    KeyIso#CNG Key Isolation#Running#Manual
    KPSSVC#KDC Proxy Server service (KPS)#Stopped#Manual
    KtmRm#KtmRm for Distributed Transaction Coordinator#Stopped#Manual
    LanmanServer#Server#Running#Automatic
    LanmanWorkstation#Workstation#Running#Automatic
    lfsvc#Geolocation Service#Running#Manual
    LicenseManager#Windows License Manager Service#Stopped#Manual
    lltdsvc#Link-Layer Topology Discovery Mapper#Stopped#Manual
    lmhosts#TCP/IP NetBIOS Helper#Running#Manual
    LSM#Local Session Manager#Running#Automatic
    MapsBroker#Downloaded Maps Manager#Stopped#Automatic
    MpsSvc#Windows Firewall#Running#Automatic
    MSDTC#Distributed Transaction Coordinator#Running#Automatic
    MSiSCSI#Microsoft iSCSI Initiator Service#Stopped#Manual
    msiserver#Windows Installer#Stopped#Manual
    NcaSvc#Network Connectivity Assistant#Stopped#Manual
    NcbService#Network Connection Broker#Running#Manual
    Netlogon#Netlogon#Stopped#Manual
    Netman#Network Connections#Running#Manual
    netprofm#Network List Service#Running#Manual
    NetSetupSvc#Network Setup Service#Stopped#Manual
    NetTcpPortSharing#Net.Tcp Port Sharing Service#Stopped#Disabled
    NgcCtnrSvc#Microsoft Passport Container#Stopped#Manual
    NgcSvc#Microsoft Passport#Stopped#Manual
    NlaSvc#Network Location Awareness#Running#Automatic
    nsi#Network Store Interface Service#Running#Automatic
    OneSyncSvc_20d8a#Sync Host_20d8a#Running#Automatic
    PcaSvc#Program Compatibility Assistant Service#Running#Automatic
    PerfHost#Performance Counter DLL Host#Stopped#Manual
    PhoneSvc#Phone Service#Stopped#Manual
    PimIndexMaintenanceSvc_20d8a#Contact Data_20d8a#Stopped#Manual
    pla#Performance Logs & Alerts#Stopped#Manual
    PlugPlay#Plug and Play#Running#Manual
    PolicyAgent#IPsec Policy Agent#Stopped#Manual
    Power#Power#Running#Automatic
    PrintNotify#Printer Extensions and Notifications#Stopped#Manual
    ProfSvc#User Profile Service#Running#Automatic
    QWAVE#Quality Windows Audio Video Experience#Stopped#Manual
    RasAuto#Remote Access Auto Connection Manager#Stopped#Manual
    RasMan#Remote Access Connection Manager#Running#Manual
    RemoteAccess#Routing and Remote Access#Stopped#Disabled
    RemoteRegistry#Remote Registry#Stopped#Automatic
    RmSvc#Radio Management Service#Stopped#Manual
    RpcEptMapper#RPC Endpoint Mapper#Running#Automatic
    RpcLocator#Remote Procedure Call (RPC) Locator#Stopped#Manual
    RpcSs#Remote Procedure Call (RPC)#Running#Automatic
    RSoPProv#Resultant Set of Policy Provider#Stopped#Manual
    sacsvr#Special Administration Console Helper#Stopped#Manual
    SamSs#Security Accounts Manager#Running#Automatic
    SCardSvr#Smart Card#Stopped#Disabled
    ScDeviceEnum#Smart Card Device Enumeration Service#Stopped#Manual
    Schedule#Task Scheduler#Running#Automatic
    SCPolicySvc#Smart Card Removal Policy#Stopped#Manual
    seclogon#Secondary Logon#Stopped#Manual
    SENS#System Event Notification Service#Running#Automatic
    SensorDataService#Sensor Data Service#Stopped#Manual
    SensorService#Sensor Service#Stopped#Manual
    SensrSvc#Sensor Monitoring Service#Stopped#Manual
    SessionEnv#Remote Desktop Configuration#Stopped#Manual
    SharedAccess#Internet Connection Sharing (ICS)#Stopped#Manual
    ShellHWDetection#Shell Hardware Detection#Running#Automatic
    smphost#Microsoft Storage Spaces SMP#Stopped#Manual
    SNMPTRAP#SNMP Trap#Stopped#Manual
    Spooler#Print Spooler#Running#Automatic
    sppsvc#Software Protection#Stopped#Automatic
    SSDPSRV#SSDP Discovery#Stopped#Manual
    SstpSvc#Secure Socket Tunneling Protocol Service#Running#Manual
    StateRepository#State Repository Service#Running#Manual
    stisvc#Windows Image Acquisition (WIA)#Stopped#Manual
    StorSvc#Storage Service#Stopped#Manual
    svsvc#Spot Verifier#Stopped#Manual
    swprv#Microsoft Software Shadow Copy Provider#Stopped#Manual
    SysMain#Superfetch#Stopped#Manual
    SystemEventsBroker#System Events Broker#Running#Automatic
    TabletInputService#Touch Keyboard and Handwriting Panel Service#Stopped#Manual
    TapiSrv#Telephony#Stopped#Manual
    TermService#Remote Desktop Services#Stopped#Manual
    Themes#Themes#Running#Automatic
    TieringEngineService#Storage Tiers Management#Stopped#Manual
    tiledatamodelsvc#Tile Data model server#Running#Automatic
    TimeBrokerSvc#Time Broker#Running#Manual
    TrkWks#Distributed Link Tracking Client#Running#Automatic
    TrustedInstaller#Windows Modules Installer#Stopped#Manual
    tzautoupdate#Auto Time Zone Updater#Stopped#Disabled
    UALSVC#User Access Logging Service#Running#Automatic
    UevAgentService#User Experience Virtualization Service#Stopped#Disabled
    UI0Detect#Interactive Services Detection#Stopped#Manual
    UmRdpService#Remote Desktop Services UserMode Port Redirector#Stopped#Manual
    UnistoreSvc_20d8a#User Data Storage_20d8a#Stopped#Manual
    upnphost#UPnP Device Host#Stopped#Manual
    UserDataSvc_20d8a#User Data Access_20d8a#Stopped#Manual
    UserManager#User Manager#Running#Automatic
    UsoSvc#Update Orchestrator Service for Windows Update#Stopped#Manual
    VaultSvc#Credential Manager#Running#Manual
    vds#Virtual Disk#Stopped#Manual
    vmicguestinterface#Hyper-V Guest Service Interface#Stopped#Manual
    vmicheartbeat#Hyper-V Heartbeat Service#Stopped#Manual
    vmickvpexchange#Hyper-V Data Exchange Service#Stopped#Manual
    vmicrdv#Hyper-V Remote Desktop Virtualization Service#Stopped#Manual
    vmicshutdown#Hyper-V Guest Shutdown Service#Stopped#Manual
    vmictimesync#Hyper-V Time Synchronization Service#Stopped#Manual
    vmicvmsession#Hyper-V PowerShell Direct Service#Stopped#Manual
    vmicvss#Hyper-V Volume Shadow Copy Requestor#Stopped#Manual
    VSS#Volume Shadow Copy#Stopped#Manual
    W32Time#Windows Time#Running#Automatic
    WalletService#WalletService#Stopped#Manual
    WbioSrvc#Windows Biometric Service#Stopped#Manual
    Wcmsvc#Windows Connection Manager#Running#Automatic
    WdiServiceHost#Diagnostic Service Host#Stopped#Manual
    WdiSystemHost#Diagnostic System Host#Stopped#Manual
    WdNisSvc#Windows Defender Network Inspection Service#Stopped#Manual
    Wecsvc#Windows Event Collector#Stopped#Manual
    WEPHOSTSVC#Windows Encryption Provider Host Service#Stopped#Manual
    wercplsupport#Problem Reports and Solutions Control Panel Support#Stopped#Manual
    WerSvc#Windows Error Reporting Service#Stopped#Manual
    WiaRpc#Still Image Acquisition Events#Stopped#Manual
    WinDefend#Windows Defender Service#Running#Automatic
    WinHttpAutoProxySvc#WinHTTP Web Proxy Auto-Discovery Service#Running#Manual
    Winmgmt#Windows Management Instrumentation#Running#Automatic
    WinRM#Windows Remote Management (WS-Management)#Running#Automatic
    wisvc#Windows Insider Service#Stopped#Manual
    wlidsvc#Microsoft Account Sign-in Assistant#Stopped#Manual
    WLMS#Windows Licensing Monitoring Service#Running#Automatic
    wmiApSrv#WMI Performance Adapter#Stopped#Manual
    WPDBusEnum#Portable Device Enumerator Service#Stopped#Manual
    WpnService#Windows Push Notifications System Service#Running#Automatic
    WpnUserService_20d8a#Windows Push Notifications User Service_20d8a#Stopped#Manual
    WSearch#Windows Search#Stopped#Disabled
    wuauserv#Windows Update#Stopped#Manual
    wudfsvc#Windows Driver Foundation - User-mode Driver Framework#Stopped#Manual
    XblAuthManager#Xbox Live Auth Manager#Stopped#Manual
    XblGameSave#Xbox Live Game Save#Stopped#Manual'

            Write-Host "Checking services...`n" -ForegroundColor Green
            [bool]$noUnknownServices = $true

            foreach($serv in get-service){
                $name = $serv.Name
                $dispName = $serv.displayname
                $status = $serv.status
                $starttype = $serv.starttype
    

        
                if (($lisaServices | %{$_ -match $name}) -contains $true) {
                    foreach ($line in $lisaServices -split "`n"){
                        $line = $line.trim()
                        if ($line -like "$name`#*"){
                            $correctStatus = $line.split("#")[2]
                            if ($line.split("#")[2]){
                                if ($status -ne $line.split("#")[2] -and $dispName -ne "SSDP Discovery" -and $dispName -ne "Superfetch"){
                                    
                                    Write-Host "Incorrect status for service.`n" -ForegroundColor Yellow
                                    Write-Host "Service: $dispName" -ForegroundColor Yellow
                                    Write-Host "Correct Status: $correctStatus `nActual Status: $status" -ForegroundColor Yellow
                                    Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
                                    Write-Host "`n`t- Such misconfigurations may disarm services that would otherwise protect the environment." -ForegroundColor Gray
                                    Write-Host "`t`t- Unneeded running services could be used by attackers to persist in the environment" -ForegroundColor Gray
                                    Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
                                    Write-Host "`n`t`t`t`t`t Determine the criticality/importance of this service." -ForegroundColor Gray
                                    Write-Host "`n`t`t`t`t`t If no one can accept responsibility for the misconfiguration, reset this to its correct status." -ForegroundColor Gray
                                    Write-Host "`n`t`t`t`t`t Conduct further investigation. Ex: Check Windows Event Logs for Windows Firewall Changes such as ID: 4950" -ForegroundColor Gray
                                    Write-Host "`n`n`n"
                                    $noUnknownServices = $false
                                }
                            }
                            else {
                                # Not sure why I have an else statement here. Probably had an idea. Will leave this here for later.
                            }
                            break       
                        }
                    }
                }
        
                else {
                        Write-Host "Additional Service Installed: $dispName" -ForegroundColor Yellow
                        Write-Host "Start type: $starttype"
                        Write-Host "Status: $status"
                        Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
                        Write-Host "`t`t- Unneeded or unknown services could be used as means of persistence." -ForegroundColor Gray
                        Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
                        Write-Host "`n`t`t`t`t`t Ensure that this service does not belong to legitimate applications or the Windows environment." -ForegroundColor Gray
                        Write-Host "`n`t`t`t`t`t Remove service immediately." -ForegroundColor Gray
                        Write-Host "`n`n`n"
                        $noUnknownServices = $false
                }
    
            }

        if ($noUnknownServices){
            Write-Host "***NO UNKNOWN SERVICES***" -ForegroundColor Green
        }
    }
    getServicesThatStandOut

    #Scheduled Task Related Information
    function getScheduledTasksThatStandOut() {


    $lisaSchTasks = ".NET Framework NGEN v4.0.30319#\Microsoft\Windows\.NET Framework\#Ready
    .NET Framework NGEN v4.0.30319 64#\Microsoft\Windows\.NET Framework\#Ready
    .NET Framework NGEN v4.0.30319 64 Critical#\Microsoft\Windows\.NET Framework\#Ready
    .NET Framework NGEN v4.0.30319 Critical#\Microsoft\Windows\.NET Framework\#Ready
    AD RMS Rights Policy Template Management (Automated)#\Microsoft\Windows\Active Directory Rights Man
    agement Services Client\#Disabled
    AD RMS Rights Policy Template Management (Manual)#\Microsoft\Windows\Active Directory Rights Manage
    ment Services Client\#Ready
    EDP Policy Manager#\Microsoft\Windows\AppID\#Ready
    PolicyConverter#\Microsoft\Windows\AppID\#Disabled
    SmartScreenSpecific#\Microsoft\Windows\AppID\#Ready
    VerifiedPublisherCertStoreCheck#\Microsoft\Windows\AppID\#Disabled
    Microsoft Compatibility Appraiser#\Microsoft\Windows\Application Experience\#Ready
    ProgramDataUpdater#\Microsoft\Windows\Application Experience\#Ready
    StartupAppTask#\Microsoft\Windows\Application Experience\#Ready
    appuriverifierdaily#\Microsoft\Windows\ApplicationData\#Ready
    appuriverifierinstall#\Microsoft\Windows\ApplicationData\#Ready
    CleanupTemporaryState#\Microsoft\Windows\ApplicationData\#Ready
    DsSvcCleanup#\Microsoft\Windows\ApplicationData\#Ready
    Pre-staged app cleanup#\Microsoft\Windows\AppxDeploymentClient\#Ready
    Proxy#\Microsoft\Windows\Autochk\#Ready
    UninstallDeviceTask#\Microsoft\Windows\Bluetooth\#Ready
    AikCertEnrollTask#\Microsoft\Windows\CertificateServicesClient\#Ready
    CryptoPolicyTask#\Microsoft\Windows\CertificateServicesClient\#Ready
    KeyPreGenTask#\Microsoft\Windows\CertificateServicesClient\#Ready
    SystemTask#\Microsoft\Windows\CertificateServicesClient\#Ready
    UserTask#\Microsoft\Windows\CertificateServicesClient\#Ready
    UserTask-Roam#\Microsoft\Windows\CertificateServicesClient\#Ready
    ProactiveScan#\Microsoft\Windows\Chkdsk\#Ready
    License Validation#\Microsoft\Windows\Clip\#Disabled
    CreateObjectTask#\Microsoft\Windows\CloudExperienceHost\#Ready
    Consolidator#\Microsoft\Windows\Customer Experience Improvement Program\#Ready
    KernelCeipTask#\Microsoft\Windows\Customer Experience Improvement Program\#Ready
    UsbCeip#\Microsoft\Windows\Customer Experience Improvement Program\#Ready
    Data Integrity Scan#\Microsoft\Windows\Data Integrity Scan\#Ready
    Data Integrity Scan for Crash Recovery#\Microsoft\Windows\Data Integrity Scan\#Ready
    ScheduledDefrag#\Microsoft\Windows\Defrag\#Ready
    Device#\Microsoft\Windows\Device Information\#Ready
    Metadata Refresh#\Microsoft\Windows\Device Setup\#Ready
    Scheduled#\Microsoft\Windows\Diagnosis\#Ready
    SilentCleanup#\Microsoft\Windows\DiskCleanup\#Ready
    Microsoft-Windows-DiskDiagnosticDataCollector#\Microsoft\Windows\DiskDiagnostic\#Ready
    Microsoft-Windows-DiskDiagnosticResolver#\Microsoft\Windows\DiskDiagnostic\#Disabled
    Diagnostics#\Microsoft\Windows\DiskFootprint\#Ready
    StorageSense#\Microsoft\Windows\DiskFootprint\#Ready
    EDP App Launch Task#\Microsoft\Windows\EDP\#Ready
    EDP Auth Task#\Microsoft\Windows\EDP\#Ready
    EnableErrorDetailsUpdate#\Microsoft\Windows\ErrorDetails\#Ready
    ErrorDetailsUpdate#\Microsoft\Windows\ErrorDetails\#Disabled
    Installation#\Microsoft\Windows\LanguageComponentsInstaller\#Ready
    Uninstallation#\Microsoft\Windows\LanguageComponentsInstaller\#Ready
    TempSignedLicenseExchange#\Microsoft\Windows\License Manager\#Ready
    Notifications#\Microsoft\Windows\Location\#Ready
    WindowsActionDialog#\Microsoft\Windows\Location\#Ready
    WinSAT#\Microsoft\Windows\Maintenance\#Ready
    MapsToastTask#\Microsoft\Windows\Maps\#Ready
    MapsUpdateTask#\Microsoft\Windows\Maps\#Disabled
    ProcessMemoryDiagnosticEvents#\Microsoft\Windows\MemoryDiagnostic\#Disabled
    RunFullMemoryDiagnostic#\Microsoft\Windows\MemoryDiagnostic\#Disabled
    MNO Metadata Parser#\Microsoft\Windows\Mobile Broadband Accounts\#Ready
    LPRemove#\Microsoft\Windows\MUI\#Ready
    SystemSoundsService#\Microsoft\Windows\Multimedia\#Disabled
    GatherNetworkInfo#\Microsoft\Windows\NetTrace\#Ready
    SDN Diagnostics Task#\Microsoft\Windows\Network Controller\#Disabled
    Background Synchronization#\Microsoft\Windows\Offline Files\#Disabled
    Logon Synchronization#\Microsoft\Windows\Offline Files\#Disabled
    Secure-Boot-Update#\Microsoft\Windows\PI\#Ready
    Sqm-Tasks#\Microsoft\Windows\PI\#Ready
    Server Manager Performance Monitor#\Microsoft\Windows\PLA\#Disabled
    Device Install Group Policy#\Microsoft\Windows\Plug and Play\#Ready
    Device Install Reboot Required#\Microsoft\Windows\Plug and Play\#Ready
    Plug and Play Cleanup#\Microsoft\Windows\Plug and Play\#Ready
    Sysprep Generalize Drivers#\Microsoft\Windows\Plug and Play\#Ready
    AnalyzeSystem#\Microsoft\Windows\Power Efficiency Diagnostics\#Ready
    MobilityManager#\Microsoft\Windows\Ras\#Ready
    VerifyWinRE#\Microsoft\Windows\RecoveryEnvironment\#Ready
    RegIdleBackup#\Microsoft\Windows\Registry\#Ready
    CleanupOldPerfLogs#\Microsoft\Windows\Server Manager\#Ready
    ServerManager#\Microsoft\Windows\Server Manager\#Ready
    StartComponentCleanup#\Microsoft\Windows\Servicing\#Ready
    BackgroundUploadTask#\Microsoft\Windows\SettingSync\#Ready
    BackupTask#\Microsoft\Windows\SettingSync\#Ready
    NetworkStateChangeTask#\Microsoft\Windows\SettingSync\#Ready
    SetupCleanupTask#\Microsoft\Windows\Setup\#Ready
    CreateObjectTask#\Microsoft\Windows\Shell\#Ready
    IndexerAutomaticMaintenance#\Microsoft\Windows\Shell\#Ready
    Collection#\Microsoft\Windows\Software Inventory Logging\#Disabled
    Configuration#\Microsoft\Windows\Software Inventory Logging\#Ready
    SvcRestartTask#\Microsoft\Windows\SoftwareProtectionPlatform\#Ready
    SvcRestartTaskLogon#\Microsoft\Windows\SoftwareProtectionPlatform\#Disabled
    SvcRestartTaskNetwork#\Microsoft\Windows\SoftwareProtectionPlatform\#Disabled
    SpaceAgentTask#\Microsoft\Windows\SpacePort\#Ready
    SpaceManagerTask#\Microsoft\Windows\SpacePort\#Ready
    SpeechModelDownloadTask#\Microsoft\Windows\Speech\#Ready
    Storage Tiers Management Initialization#\Microsoft\Windows\Storage Tiers Management\#Ready
    Storage Tiers Optimization#\Microsoft\Windows\Storage Tiers Management\#Disabled
    Interactive#\Microsoft\Windows\Task Manager\#Ready
    MsCtfMonitor#\Microsoft\Windows\TextServicesFramework\#Running
    ForceSynchronizeTime#\Microsoft\Windows\Time Synchronization\#Ready
    SynchronizeTimeZone#\Microsoft\Windows\Time Zone\#Ready
    Tpm-HASCertRetr#\Microsoft\Windows\TPM\#Ready
    Tpm-Maintenance#\Microsoft\Windows\TPM\#Ready
    Maintenance Install#\Microsoft\Windows\UpdateOrchestrator\#Disabled
    Policy Install#\Microsoft\Windows\UpdateOrchestrator\#Disabled
    Reboot#\Microsoft\Windows\UpdateOrchestrator\#Ready
    Refresh Settings#\Microsoft\Windows\UpdateOrchestrator\#Ready
    Resume On Boot#\Microsoft\Windows\UpdateOrchestrator\#Disabled
    Schedule Scan#\Microsoft\Windows\UpdateOrchestrator\#Ready
    USO_UxBroker_Display#\Microsoft\Windows\UpdateOrchestrator\#Ready
    USO_UxBroker_ReadyToReboot#\Microsoft\Windows\UpdateOrchestrator\#Ready
    UPnPHostConfig#\Microsoft\Windows\UPnP\#Ready
    HiveUploadTask#\Microsoft\Windows\User Profile Service\#Disabled
    ResolutionHost#\Microsoft\Windows\WDI\#Ready
    Windows Defender Cache Maintenance#\Microsoft\Windows\Windows Defender\#Ready
    Windows Defender Cleanup#\Microsoft\Windows\Windows Defender\#Ready
    Windows Defender Scheduled Scan#\Microsoft\Windows\Windows Defender\#Ready
    Windows Defender Verification#\Microsoft\Windows\Windows Defender\#Ready
    QueueReporting#\Microsoft\Windows\Windows Error Reporting\#Ready
    BfeOnServiceStartTypeChange#\Microsoft\Windows\Windows Filtering Platform\#Ready
    Calibration Loader#\Microsoft\Windows\WindowsColorSystem\#Disabled
    Automatic App Update#\Microsoft\Windows\WindowsUpdate\#Ready
    Scheduled Start#\Microsoft\Windows\WindowsUpdate\#Ready
    sih#\Microsoft\Windows\WindowsUpdate\#Ready
    sihboot#\Microsoft\Windows\WindowsUpdate\#Ready
    CacheTask#\Microsoft\Windows\Wininet\#Running
    Automatic-Device-Join#\Microsoft\Windows\Workplace Join\#Disabled
    XblGameSaveTask#\Microsoft\XblGameSave\#Ready
    XblGameSaveTaskLogon#\Microsoft\XblGameSave\#Ready
    MusUx_UpdateInterval#\\Microsoft\Windows\UpdateOrchestrator\#Ready"

    $fullListOfSchTasks = ".NETFramework
.NETFrameworkNGENv4.0.30319
.NETFrameworkNGENv4.0.3031964
.NETFrameworkNGENv4.0.3031964Critical
.NETFrameworkNGENv4.0.30319Critical
AccountCleanup
ActiveDirectoryRightsManagementServicesClient
ADRMSRightsPolicyTemplateManagement(Automated)
ADRMSRightsPolicyTemplateManagement(Manual)
AikCertEnrollTask
AnalyzeSystem
AppID
ApplicationExperience
applicationdata
appuriverifierdaily
appuriverifierinstall
AppxDeploymentClient
Autochk
Automatic-Device-Join
BackgroundSynchronization
BackgroundUploadTask
BfeOnServiceStartTypeChange
BgTaskRegistrationMaintenanceTask
BitLocker
BitLockerMDMpolicyRefresh
Bluetooth
BrokerInfrastructure
CacheTask
CalibrationLoader
Cellular
CertificateServicesClient
Chkdsk
CleanupTemporaryState
Clip
CloudExperienceHost
Consolidator
CreateObjectTask
CreateObjectTask
CryptoPolicyTask
CustomerExperienceImprovementProgram
DataIntegrityScan
DataIntegrityScan
DataIntegrityScanforCrashRecovery
Defrag
Device
DeviceInformation
DeviceInstallGroupPolicy
DeviceInstallRebootRequired
DeviceSetup
DeviceDirectoryClient
Diagnosis
Diagnostics
DirectX
DiskCleanup
DiskDiagnostic
DiskFootprint
DmClient
DmClientOnScenarioDownload
DsSvcCleanup
DUSM
dusmtask
DXGIAdapterCache
EDP
EDPAppLaunchTask
EDPAuthTask
EDPInaccessibleCredentialsTask
EDPPolicyManager
EduPrintProv
EnableLicenseAcquisition
ExploitGuard
ExploitGuardMDMpolicyRefresh
FamilySafetyMonitor
FamilySafetyMonitorToastTask
FamilySafetyRefreshTask
Feedback
FileClassificationInfrastructure
FileHistory(maintenancemode)
FileHistory
FODCleanupTask
ForceSynchronizeTime
GatherNetworkInfo
HandleCommand
HandleWnsCommand
HeadsetButtonPress
HelloFace
HiveUploadTask
HybridDriveCachePrepopulate
HybridDriveCacheRebalance
IndexerAutomaticMaintenance
Installation
InstallService
IntegrityCheck
Interactive
KeyPreGenTask
LanguageComponentsInstaller
LicenseManager
LicenseValidation
LicenseAcquisition
Live
LocateCommandUserSession
Location
LoginCheck
Logon
LogonSynchronization
LPRemove
Maintenance
MaintenanceInstall
Management
Maps
MapsToastTask
MapsUpdateTask
MemoryDiagnostic
MetadataRefresh
Microsoft
MicrosoftCompatibilityAppraiser
Microsoft-Windows-DiskDiagnosticDataCollector
Microsoft-Windows-DiskDiagnosticResolver
MNOMetadataParser
MobileBroadbandAccounts
MobilityManager
MsCtfMonitor
MUI
Multimedia
NetTrace
NetworkStateChangeTask
NlaSvc
Notifications
NotificationTask
OfflineFiles
OneDriveStandaloneUpdateTask-S-1-5-21-690249082-3703318214-1872523464-1001
PerformRemediation
PI
PLA
PlugandPlay
PolicyConverter
PowerEfficiencyDiagnostics
Pre-stagedappcleanup
Printing
ProactiveScan
ProcessMemoryDiagnosticEvents
ProgramDataUpdater
PropertyDefinitionSync
Provisioning
Proxy
PushToInstall
QueueReporting
Ras
Reboot
ReconcileLanguageResources
Recovery-Check
RecoveryEnvironment
RegIdleBackup
RegisterDeviceAccountChange
RegisterDeviceLocationRightsChange
RegisterDevicePeriodic24
RegisterDevicePolicyChange
RegisterDeviceProtectionStateChanged
RegisterDeviceSettingChange
RegisterDeviceWnsFallback
RegisterUserDevice
Registration
Registry
RemoteAppandDesktopConnectionsUpdate
RemoteAssistance
RemoteAssistanceTask
rempl
ResolutionHost
ResPriStaticDbSync
RetailDemo
Roaming
RunFullMemoryDiagnostic
RunUpdateNotificationMgr
ScanForUpdates
ScanForUpdatesAsUser
ScheduleScan
Scheduled
ScheduledStart
ScheduledDefrag
Secure-Boot-Update
Servicing
SettingSync
SharedPC
shell
Shell
sih
SilentCleanup
Siuf
SmartRetry
SoftwareProtectionPlatform
SpaceAgentTask
SpaceManagerTask
SpacePort
Speech
SpeechModelDownloadTask
Sqm-Tasks
SR
StartComponentCleanup
StartupAppTask
StorageTiersManagement
StorageTiersManagementInitialization
StorageTiersOptimization
StorageCardEncryptionTask
StorageSense
Subscription
SvcRestartTask
SvcRestartTaskLogon
SvcRestartTaskNetwork
SyncCenter
SynchronizeTime
SynchronizeTimeZone
Sysmain
SyspartRepair
SysprepGeneralizeDrivers
System
SystemRestore
SystemSoundsService
SystemTask
TaskManager
TaskScheduler
TempSignedLicenseExchange
TextServicesFramework
TimeSynchronization
TimeZone
TPM
Tpm-HASCertRetr
Tpm-Maintenance
Uninstallation
UninstallDeviceTask
UNP
UpdateLibrary
UpdateOrchestrator
UPnP
UPnPHostConfig
USB
UsbCeip
Usb-Notifications
UserProfileService
UserTask
UserTask-Roam
USO_Broker_Display
VerifiedPublisherCertStoreCheck
VerifyWinRE
WaaSMedic
WakeUpAndContinueUpdates
WakeUpAndScanForUpdates
WCM
WDI
WiFiTask
WiFiTask
WIM-Hash-Management
WIM-Hash-Validation
Windows
WindowsActivationTechnologies
WindowsDefender
WindowsDefenderCacheMaintenance
WindowsDefenderCleanup
WindowsDefenderScheduledScan
WindowsDefenderVerification
WindowsErrorReporting
WindowsFilteringPlatform
WindowsMediaSharing
WindowsSubsystemForLinux
WindowsActionDialog
WindowsBackup
WindowsColorSystem
WindowsUpdate
Wininet
WinSAT
WOF
WorkFolders
WorkFoldersLogonSynchronization
WorkFoldersMaintenanceWork
WorkplaceJoin
WS
WsSwapAssessmentTask
WwanSvc
XblGameSave
XblGameSaveTask"

    Write-Host "Checking scheduled tasks...`n" -ForegroundColor Green

    #Goes through each driver in the victim's box individually.
    foreach ($suspectTask in get-scheduledtask) {
        $name = $suspectTask.TaskName
        #Assumes the individual driver is malicious.
        $maliciousTask = $True
        foreach ($line in (($fullListOfSchTasks) | out-string) -split "`n"){
            
            #If the driver that we assume is malicious is found in the clean kernel list, we change our assumption from true to false.
            if ($name -like "$line*"){
                $maliciousTask = $False
                
            }
        }

        #If we never changed our assumption.
        if ($maliciousTask){
            Write-Host "Suspect Task Found: $name"
            
        }
    }
    



    foreach($task in get-scheduledtask){

        $name = $task.taskname
        $path = $task.taskpath
        $state = $task.state

        if (($lisaSchTasks | %{$_ -match $name}) -contains $true) {
            foreach ($line in $lisaSchTasks -split "`n"){
                if ($line -like "$name`#*"){
                    $correctpath = $line.split("#")[1]
                

                    if ($line.split("#")[1]){
                        if ($path -ne $line.split("#")[1] -and $line -notlike "OneDrive*" -and $line -notlike "User_Feed*" -and $line -notlike "WifiTask*" -and $line -notlike "CreateObjectTask*"){
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


        else {
            if ($name -like "*OneDrive*" -or $name -like "*User_Feed*" -or $name -like "*AD RMS*" -or $name -eq "File History (maintenance mode)" -or $name -eq "OSCleanup"){
                continue;
            }
            else {
                
                Write-Host "Additional Task Found in Scheduled Tasks." -Foregroundcolor Yellow
                Write-Host "`tName of Scheduled Task: $name" -Foregroundcolor Yellow
                Write-Host "`tPath of Scheduled Task: $path" -Foregroundcolor Yellow
                Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
                Write-Host "`t`t- Scheduled Tasks are a common way of executing malicious activity covertly such as during after-work hours." -ForegroundColor Gray
                Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
                Write-Host "`n`t`t`t`t`t Remove task(s) immediately if no one can take responsibility for this task." -ForegroundColor Gray
                Write-Host "`n`n`n"
                            
            
            
                Write-Host "`n"
            
            }
        }    

    }

    }
    getScheduledTasksThatStandOut

    #Check Host
    function checkHostsFile(){
        if ((gci 'C:\Windows\System32\drivers\etc\hosts').attributes -ne "Archive","ReadOnly"){
                Write-Host "'C:\Windows\System32\drivers\etc\hosts' File is not read-only" -Foregroundcolor Yellow
                Write-Host "`n`tWhy make the Hosts file read only?`n" -ForegroundColor Gray
                Write-Host "`t`t- Malware can redirect your Web addresses to malicious sites; known as Host File Hijack." -ForegroundColor Gray
                Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
                Write-Host "`n`t`t`t`t`t- Run the following command as Administrator:" -ForegroundColor Gray
                Write-Host "`t`t`t`t`t`t gci C:\Windows\System32\drivers\etc\hosts | % {`$_.Attributes=`"Archive`",`"ReadOnly}`"" -ForegroundColor Gray
                Write-Host "`n`n`n"
        }
        foreach ($line in (gc 'C:\Windows\System32\drivers\etc\hosts')){
            if ($line -notlike "#*" -and $line -notlike ""){
                Write-Host "Extra entry added to hosts file." -ForegroundColor Yellow
                Write-Host $line
                Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
                Write-Host "`t`t- Malware can redirect your Web addresses to malicious sites; known as Host File Hijack." -ForegroundColor Gray
                Write-Host "`t`t- $line could be a redirection" -ForegroundColor Gray
                Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
                Write-Host "`n`t`t`t`t`t- Delete $line if no one can account for it." -ForegroundColor Gray
                Write-Host "`n`n`n"
            }
        }
    }
    checkHostsFile

    #Check Port Filters on Firewall
    function checkPortFiltersOnFirewall(){
        if ((Get-NetFirewallPortFilter).count -ne 209){
            Write-Host "Port filters on Windows Firewall have changed" -Foregroundcolor Yellow
            Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
            Write-Host "`t`t- It just is, okay?" -ForegroundColor Gray
            Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
            Write-Host "`n`t`t`t`t`t- Check the Windows Firewall and investigate further." -ForegroundColor Gray
            Write-Host "`n`n`n"
        }
    }
    checkPortFiltersOnFirewall

    $menu = Read-Host "Press any key to return to the main menu"
    clear
}

function ps1(){
clear
Write-Host "     
                 
                    _=====_                               _=====_
                   / _____ \                             / _____ \
                 +.-'_____'-.---------------------------.-'_____'-.+
                /   |     |  '.     PLAYSTATION 1     .'  |  _  |   \
               / ___| /|\ |___ \                     / ___| /_\ |___ \
              / |      |      | ;  __           __  ; | _         _ | ;
              | | <---   ---> | | |__|         |__| | ||_|       (_)| |
              | |___   |   ___| ;SELECT       START ; |___       ___| ;
              |\    | \|/ |    /  _     ___      _   \    | (X) |    /|
              | \   |_____|  .','" "', |___|  ,'" "', '.  |_____|  .' |
              |  '-.______.-' /       \ANALOG/       \  '-._____.-'   |
              |               |       |------|       |                |
              |              /\       /      \       /\               |
              |             /  '.___.'        '.___.'  \              |
              |            /                            \             |
               \          /                              \           /
                \________/                                \_________/
`n" -ForegroundColor Gray
Sleep (3)

# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
# Anything in this registry key path automatically executes when any user logs on.

$HKLM_Run = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
if (($HKLM_Run).ValueCount -gt 1) {
      Write-Host "Potential threat found in: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ForegroundColor Yellow "`n`n"
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Anything in this registry key path automatically executes when any user logs on.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present. Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'`n`n" -ForegroundColor Gray
      Write-Host "   'SecurityHealth'" -ForegroundColor DarkYellow -NoNewline
      Write-Host "should be the only value provided in the Property field. Conduct further analysis if any other values are present." -ForegroundColor Gray
      Write-Host ($HKLM_Run | Out-String) -ForegroundColor DarkYellow
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
}

# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
# Anything in this registry key path automatically executes when any user logs on.

$HKLM_RunOnce = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
if (($HKLM_RunOnce).ValueCount -gt 0) {
      Write-Host "Potential threat found in: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ForegroundColor Yellow "`n`n"
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Anything in this registry key path automatically executes when any user logs on.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present. Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'`n`n" -ForegroundColor Gray
      Write-Host "    There should be no value provided in the Property field. Conduct further analysis if any other values are present." -ForegroundColor Gray
      Write-Host ($HKLM_RunOnce | Out-String) -ForegroundColor DarkYellow
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
}

# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Command Processor
# Anything in this registry key path automatically executes when any user logs on.

$HKLM_Autorun = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Command Processor"
if ($HKLM_Autorun | Where-Object {$_.property -eq "Autorun"}) { 
      Write-Host "Potential threat found in: HKLM:\SOFTWARE\Microsoft\Command Processor" -ForegroundColor Yellow
      Write-Host "   
      Why is this a potential threat?
          
          - Anything in this registry key path automatically executes when any user logs on.
      
      Course of action if a potential threat is found:
           
           1. Get-Item -Path 'HKLM:\SOFTWARE\Microsoft\Command Processor'
           2. Conduct further analysis on the file path found in the Autorun field.     
                    - Example: Get-Content -path 'C:\users\public\malware.bat'" -ForegroundColor Gray "`n"
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
}

# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell
# Anything in this registry key path automatically executes when any user logs on.

$HKLM_Shell= (Get-ItemProperty -path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\").shell
if (!$HKLM_Shell) 
    { break }
if ($HKLM_Shell -ne "explorer.exe")     
    { Write-Host "Potential threat found in: HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon""`n`n" -ForegroundColor Yellow
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Anything in this registry key path automatically executes when any user logs on.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present. Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'`n`n" -ForegroundColor Gray
      Write-Host "    explorer.exe" -ForegroundColor DarkYellow -NoNewline
      Write-Host " should be the only value provided below.`n" -ForegroundColor Gray
      Write-Host "    $HKLM_Shell`n" -ForegroundColor DarkYellow
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n" -ForegroundColor Gray
    }

# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
# Anything in this registry key path automatically executes when any user logs on.

$HKLM_RunServices = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
if (!$HKLM_RunServices)
    { break }
if (($HKLM_RunServices).ValueCount -gt 0) 
    { Write-Host "Potential threat found in: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices" -ForegroundColor Yellow "`n`n"
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Anything in this registry key path automatically executes when any user logs on.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present. Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'`n`n" -ForegroundColor Gray
      Write-Host ($HKLM_RunServices | Out-String) -ForegroundColor DarkYellow
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
    }

# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce
# Anything in this registry key path automatically executes when any user logs on.

$HKLM_RunServicesOnce = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
if (!$HKLM_RunServicesOnce)
    { break }
if (($HKLM_RunServicesOnce).ValueCount -gt 0) 
    { Write-Host "Potential threat found in: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce" -ForegroundColor Yellow "`n`n"
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Anything in this registry key path automatically executes when any user logs on.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present. Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'`n`n" -ForegroundColor Gray
      Write-Host ($HKLM_RunServicesOnce | Out-String) -ForegroundColor DarkYellow
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
    }

# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce
# Anything in this registry key path automatically executes when any user logs on.

$HKLM_RunOnceEx = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx"
if (!$HKLM_RunOnceEx)
    { break }
if (($HKLM_RunOnceEx).ValueCount -gt 0) 
    { Write-Host "Potential threat found in: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx" -ForegroundColor Yellow "`n`n"
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Anything in this registry key path automatically executes when any user logs on.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present. Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'`n`n" -ForegroundColor Gray
      Write-Host ($HKLM_RunOnceEx | Out-String) -ForegroundColor DarkYellow
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
    }

# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
# Anything in this registry key path automatically executes when any user logs on.

$HKLM_ExplorerRun = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
if (!$HKLM_ExplorerRun)
    { break }
if (($HKLM_ExplorerRun).ValueCount -gt 0) 
    { Write-Host "Potential threat found in: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -ForegroundColor Yellow "`n`n"
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Anything in this registry key path automatically executes when any user logs on.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present. Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'`n`n" -ForegroundColor Gray
      Write-Host ($HKLM_ExplorerRun | Out-String) -ForegroundColor DarkYellow
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
    }

# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify
# Anything in this registry key path automatically executes when any user logs on.

$HKLM_Notify = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
if (!$HKLM_Notify)
    { break }
if (($HKLM_Notify).ValueCount -gt 0) 
    { Write-Host "Potential threat found in: HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify" -ForegroundColor Yellow "`n`n"
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Anything in this registry key path automatically executes when any user logs on.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present. Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'`n`n" -ForegroundColor Gray
      Write-Host ($HKLM_Notify | Out-String) -ForegroundColor DarkYellow
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
    }

# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit.exe
# Anything in this registry key path automatically executes when any user logs on.

$HKLM_Userinit = (Get-ItemProperty -path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\").Userinit
if (!$HKLM_Userinit) 
    { break } 
if ($HKLM_Userinit -ne "C:\windows\system32\userinit.exe,")      
    { Write-Host "Potential threat found in: HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon""`n`n" -ForegroundColor Yellow
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Anything in this registry key path automatically executes when any user logs on.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present. Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'`n`n" -ForegroundColor Gray
      Write-Host "    C:\windows\system32\userinit.exe," -ForegroundColor DarkYellow -NoNewline
      Write-Host " should be the only value provided below.`n" -ForegroundColor Gray
      Write-Host "    $HKLM_Userinit`n" -ForegroundColor DarkYellow
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n" -ForegroundColor Gray
    }

# HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad
# Anything in this registry key path automatically executes when any user logs on.

$HKLM_ShellServiceObjectDelayLoad = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad"
if (($HKLM_ShellServiceObjectDelayLoad).ValueCount -gt 0) {
      Write-Host "Potential threat found in: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad" -ForegroundColor Yellow "`n`n"
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Anything in this registry key path automatically executes when any user logs on.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present. Example: Google information regarding present GUID" -ForegroundColor Gray
      Write-Host ($HKLM_ShellServiceObjectDelayLoad | Out-String) -ForegroundColor DarkYellow
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
}

# HKEY_LOCAL_MACHINE\SOFTWARE\\Microsoft\Windows NT\CurrentVersion\Windows\
# Values listed in AppInit_DLLs are loaded when any process is started.

$HKLM_AppInit_DLLs = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows\" -Name AppInit_DLLs)
if (($HKLM_AppInit_DLLs).ValueCount -gt 0) {
      Write-Host "Potential threat found in: HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows\" -ForegroundColor Yellow "`n`n"
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Values listed in AppInit_DLLs are loaded when any process is started.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present in the AppInit_DLLs field. Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'" -ForegroundColor Gray
      Write-Host ($HKLM_AppInit_DLLs | Out-String) -ForegroundColor DarkYellow
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
}

# HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager
# Smss.exe will launch anything present in the BootExecute key at HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager.

$HKLM_BootExecute = ((Get-ItemProperty -Path "HKLM:\\SYSTEM\ControlSet001\Control\Session Manager").bootexecute)
if (!$HKLM_BootExecute) 
    { break }
if ($HKLM_BootExecute -ne "autocheck autochk *")
    { Write-Host "Potential threat found in: HKLM:\\SYSTEM\ControlSet001\Control\Session Manager""`n`n" -ForegroundColor Yellow
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Smss.exe will launch anything present in the BootExecute key at HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Session Manager.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present. Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'`n`n" -ForegroundColor Gray
      Write-Host "           autocheck autochk *" -ForegroundColor DarkYellow -NoNewline
      Write-Host " should be the only value provided below.`n" -ForegroundColor Gray
      Write-Host "           $HKLM_BootExecute" -ForegroundColor DarkYellow
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
    }

# HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
# Anything in this registry key path automatically executes when the current user logs on.

$HKCU_Run = Get-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
if (($HKCU_Run).ValueCount -gt 1) {
     Write-Host "Potential threat found in: HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ForegroundColor Yellow "`n`n"
      Write-Host "   'SecurityHealth'" -ForegroundColor DarkYellow -NoNewline
      Write-Host "should be the only value provided in the Property field. Conduct further analysis if any other values are present." -ForegroundColor Gray
      Write-Host ($HKCU_Run | Out-String) -ForegroundColor Gray
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
}

# HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
# Anything in this registry key path automatically executes when the current user logs on.

$HKCU_RunOnce = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
if (($HKCU_RunOnce).ValueCount -gt 0) {
      Write-Host "Potential threat found in: HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -ForegroundColor Yellow "`n`n"
      Write-Host "   'SecurityHealth'" -ForegroundColor DarkYellow -NoNewline
      Write-Host "should be the only value provided in the Property field. Conduct further analysis if any other values are present." -ForegroundColor Gray
      Write-Host ($HKCU_RunOnce | Out-String) -ForegroundColor Gray
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
}

# HKEY_CURRENT_USER\SOFTWARE\Microsoft\Command Processor
# Anything in this registry key path automatically executes when the current user logs on.

$HKCU_Autorun = Get-Item -Path "HKCU:\SOFTWARE\Microsoft\Command Processor"
if ($HKCU_Autorun | Where-Object {$_.property -eq "Autorun"}) { 
      Write-Host "Potential threat found in: HKCU:\SOFTWARE\Microsoft\Command Processor" -ForegroundColor Yellow
      Write-Host "   
      Why is this a potential threat?
          
          - Anything in this registry key path automatically executes when the current user logs on.
      
      Course of action if a potential threat is found:
           
           1. Get-Item -Path 'HKCU:\SOFTWARE\Microsoft\Command Processor'
           2. Conduct further analysis on the file path found in the Autorun field.     
                    - Example: Get-Content -path 'C:\users\public\malware.bat'" -ForegroundColor Gray "`n"
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
}

# HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell
# Anything in this registry key path automatically executes when any user logs on.

$HKCU_Shell= (Get-ItemProperty -path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\").shell
if (!$HKCU_Shell) 
    { break }
if ($HKCU_Shell -ne "explorer.exe")     
    { Write-Host "Potential threat found in: HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon""`n`n" -ForegroundColor Yellow
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Anything in this registry key path automatically executes when any user logs on.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present. Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'`n`n" -ForegroundColor Gray
      Write-Host "    explorer.exe" -ForegroundColor DarkYellow -NoNewline
      Write-Host " should be the only value provided below.`n" -ForegroundColor Gray
      Write-Host "    $HKCU_Shell`n" -ForegroundColor DarkYellow
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n" -ForegroundColor Gray
    }

    # HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
# Anything in this registry key path automatically executes when any user logs on.

$HKCU_RunServices = Get-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"
if (!$HKCU_RunServices)
    { break }
if (($HKCU_RunServices).ValueCount -gt 0) 
    { Write-Host "Potential threat found in: HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices" -ForegroundColor Yellow "`n`n"
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Anything in this registry key path automatically executes when any user logs on.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present. Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'`n`n" -ForegroundColor Gray
      Write-Host ($HKCU_RunServices | Out-String) -ForegroundColor DarkYellow -NoNewline
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
    }

# HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce
# Anything in this registry key path automatically executes when any user logs on.

$HKCU_RunServicesOnce = Get-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"
if (!$HKCU_RunServicesOnce)
    { break }
if (($HKCU_RunServicesOnce).ValueCount -gt 0) 
    { Write-Host "Potential threat found in: HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices" -ForegroundColor Yellow "`n`n"
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Anything in this registry key path automatically executes when any user logs on.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present. Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'`n`n" -ForegroundColor Gray
      Write-Host ($HKCU_RunServicesOnce | Out-String) -ForegroundColor DarkYellow -NoNewline
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
    }

# HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
# Anything in this registry key path automatically executes when any user logs on.

$HKCU_ExplorerRun = Get-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
if (!$HKCU_ExplorerRun)
    { break }
if (($HKCU_ExplorerRun).ValueCount -gt 0) 
    { Write-Host "Potential threat found in: HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" -ForegroundColor Yellow "`n`n"
      Write-Host "    Why is this registry key value potential threat?`n`n" -ForegroundColor Gray
      Write-Host "           - Anything in this registry key path automatically executes when any user logs on.`n`n" -ForegroundColor Gray
      Write-Host "    Course of action if a potential threat is found:`n`n" -ForegroundColor Gray
      Write-Host "           - Conduct further analysis if any values are present. Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'`n`n" -ForegroundColor Gray
      Write-Host ($HKCU_ExplorerRun | Out-String) -ForegroundColor DarkYellow
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
    }

# Startup Folder
# Anything in this folder automatically executes when any user logs on.

$Folder_Startup = Get-ChildItem -Force "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
if (($Folder_Startup).count -gt 1) {
      Write-Host "Potential threat found in: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" -ForegroundColor Yellow
      Write-Host "     
        Why is this a potential threat?
           
           - Anything in this folder automatically executes when any user logs on.

        Course of action if a potential threat is found:

            1. Get-ChildItem -Force -Path 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'
            2. Conduct further analysis on the files found in the 'Startup' folder" -ForegroundColor Gray "`n"
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
}

# profile.ps1 executes automatically when any user logs into the computer
# If profile.ps1 is found in $PSHOME, Get-Content profile.ps1 and verify no malicious activity is taking place
# Powershell will not run correctly if Profile.Ps1 name is changed. 

if (Get-ChildItem $PSHOME | Where-Object {$_.Name -like "*profile.ps1"}) {
      Write-Host "Potential threat found in: C:\Windows\System32\WindowsPowerShell\v1.0" -ForegroundColor Yellow
      Write-Host "
        Why is this a potential threat?
           
           - 'Profile.ps1' executes automatically when any user logs into the computer. 

        Course of action if 'Profile.ps1' is found:

            1. Get-Content -Path C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1
            2. Conduct further analysis on the content in profile.ps1
                     - Example: Get-Content -Path 'C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1'" -ForegroundColor Gray "`n"
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
}

if (($env:path | Out-String).Split(";").Count -gt 6) {

    $PathsAdded = ($env:path | Out-String).Split(";").Count - 7   
      Write-Host "Potential threat found in: `$env:path" -ForegroundColor Yellow
      Write-Host "
      What is the potential threat?

             - By default, `$env:path has 6 pre-defined paths it checks in order. There is currently more than 6 paths set in this environmental variable meaning $PathsAdded has been added.
               The example provided below is the correct path.`n" -ForegroundColor Gray 
      Write-Host "                    - Example: C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;
                               C:\Users\terry\AppData\Local\Microsoft\WindowsApps;`n" -ForegroundColor DarkYellow
        
      Write-Host "      Course of action if a potential threat is found: 

            1. Compare the example given above to `$env:path to find discrepancies.
            2. Conduct analysis on all folder paths that do not match the example given.
                     - Example: Get-ChildItem -Force -Path 'C:\Users\Public\Documents'
            3. Conduct further analysis on files present.
                     - Example: Get-Content -force -Path 'C:\Users\Public\Documents\malware.sct'" -ForegroundColor Gray "`n"
      Write-Host $env:path -ForegroundColor DarkYellow
      Write-Host "_____________________________________________________________________________________________________________________________________________________________________`n`n" -ForegroundColor Gray
      }

}

function getForensicInfo(){
    Write-Host "Forensic Report`n`n`n" -ForegroundColor Green

    #Check Prefetch Files [Will add a function that infinitely loops while checking for CMD.exe, Powershell.exe, WINRAR and other IOCs]
    function getPrefetchInformation(){
        if (!(gci c:\windows\prefetch)){
                Write-Host "Prefetch not activated" -Foregroundcolor Yellow
                Write-Host "`n`tWhy enable prefetch?`n" -ForegroundColor Gray
                Write-Host "`t`t- Prefetch helps analysts figure out exactly what was done to a machine by displaying recently accessed executables." -ForegroundColor Gray
                Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
                Write-Host "`n`t`t`t`t`t Run the following commands to activate prefetch:" -ForegroundColor Gray
                Write-Host "`t`t`t`t`t`treg add`'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`' /v EnablePrefetch /t REG_DWORD /d 3 /f" -ForegroundColor Gray
                Write-Host "`t`t`t`t`t`treg add 'HKEY_LOCAL_MACHINE\software\microsoft\windows nt\currentversion\prefetcher`' /v MaxPrefetchFiles /t REG_DWORD /d 8192 /f" -ForegroundColor Gray
                Write-Host "`t`t`t`t`t`tEnable-MMAgent -operationapi" -ForegroundColor Gray
                Write-Host "`t`t`t`t`t`tnet start sysmain`n" -ForegroundColor Gray
                Write-Host "`t`t`t`t`t`tAccess the Prefetch files with the command `"get-childitem c:\windows\prefetch`"" -ForegroundColor Gray
                Write-Host "`n`n`n"
        }
        else {
            Write-Host "Recently Accessed Executables Sorted from First to Last" -ForegroundColor Yellow
            gci c:\windows\prefetch | sort lastaccesstime | select name, lastaccesstime | out-string
        }
    }
    getPrefetchInformation

    #Check Typed URLs
    function getTypedURLs(){
        get-item 'hkcu:\software\microsoft\internet explorer\typedurls'
    }
    Write-Host "Recently Accessed URLs by Internet Explorer" -ForegroundColor Yellow
    getTypedURLs
    sleep(1)



    #Check Temporary Files
    function getTemporaryFiles(){
        gci -force $env:TEMP | out-string
    }
    Write-Host "Temporary Files" -ForegroundColor Yellow
    getTemporaryFiles
    sleep(1)


    #Active network connections
    Write-Host "Active Network Connections" -ForegroundColor Yellow
    Write-Host
    $obj=@()

    Foreach($p In (Get-Process -IncludeUserName | where {$_.UserName} | `
      select Id, ProcessName, UserName)) {
          $properties = @{ 'PID'=$p.Id;
                           'ProcessName'=$p.ProcessName;
                           'UserName'=$p.UserName;
                         }
          $psobj = New-Object -TypeName psobject -Property $properties
          $obj+=$psobj
      }

    Get-NetTCPConnection | where {$_.State -eq "Established"} | select `
      RemoteAddress, `
      RemotePort, `
      @{n="PID";e={$_.OwningProcess}}, @{n="ProcessName";e={($obj |? PID -eq $_.OwningProcess | select -ExpandProperty ProcessName)}}, `
      @{n="UserName";e={($obj |? PID -eq $_.OwningProcess | select -ExpandProperty UserName)}} |
      sort -Property ProcessName, UserName |
      ft -auto

    #Listening/Open Ports
    Write-Host "Listening/Open Ports" -ForegroundColor Yellow
    Write-Host
    $obj=@()

    Foreach($p In (Get-Process -IncludeUserName | where {$_.UserName} | `
      select Id, ProcessName, UserName)) {
          $properties = @{ 'PID'=$p.Id;
                           'ProcessName'=$p.ProcessName;
                           'UserName'=$p.UserName;
                         }
          $psobj = New-Object -TypeName psobject -Property $properties
          $obj+=$psobj
      }

    Get-NetTCPConnection | where {$_.State -eq "Listen"} | select `
      LocalAddress, `
      LocalPort, `
      @{n="PID";e={$_.OwningProcess}}, @{n="ProcessName";e={($obj |? PID -eq $_.OwningProcess | select -ExpandProperty ProcessName)}}, `
      @{n="UserName";e={($obj |? PID -eq $_.OwningProcess | select -ExpandProperty UserName)}} |
      sort -Property localport |
      ft -auto







    #Get any shadow copies
    get-wmiobject -class win32_ShadowCopy




    #Get DNS Cache

    function getDNScache(){
        ipconfig /displaydns | select-string 'Record Name' | % { $_.ToString().Split(' ')[-1]} | sort
    }
    Write-Host "DNS Cache" -ForegroundColor Yellow
    getDNScache

    Write-Host "`n`n`n"
    
    $menu = Read-Host "Press any key to return to the main menu..."
    clear

    #Get Program Data Artifacts
    # gci -recurse $env:ProgramData | select fullname
 }

function advancedRegistryCheck(){

}
clear

menu

#  invoke-command DESKTOP-3F5DH7U {
        
    #} -credential $mycred

