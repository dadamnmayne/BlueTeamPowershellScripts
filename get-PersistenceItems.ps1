$misconfigCount = 0
clear



sleep (2)

Write-Host "Checking for persistence items...`n" -Foregroundcolor Green

sleep(2)

if ((get-childitem -force 'HKLM:\software\microsoft\' | ? {$_.property -eq "Autorun"}))  {
    $misconfigCount++
    Write-Host "$misconfigCount`. HKLM:\Software\Microsoft contain Autoruns" -ForegroundColor Yellow
    Write-Host "`n`t" ((gci -force 'HKLM:\SOFTWARE\Microsoft' | out-string) -split "`n" | select-string Autorun | out-string).replace("Autorun            :","").trim() -ForegroundColor Yellow
    Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
    Write-Host "`t`t- Could be used so that malware can persist." -ForegroundColor Gray
    Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
    Write-Host "`n`n`n"
}

sleep(1)

if ((Get-Item 'HKLM:\software\microsoft\windows\CurrentVersion\run').ValueCount -gt 1){
    $misconfigCount++
    Write-Host "$misconfigCount`. Additional Keys in Windows\CurrentVersion\Run" -ForegroundColor Yellow
    $x = ((Get-Item 'HKLM:\software\microsoft\windows\CurrentVersion\run' | out-string) -split "`n").length
    Write-Host "`n`t" (((Get-Item 'HKLM:\software\microsoft\windows\CurrentVersion\run' | out-string) -split "`n")[8..$x] | out-string).trim() -ForegroundColor Yellow
    Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
    Write-Host "`t`t- Could be used so that malware can persist." -ForegroundColor Gray
    Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
    Write-Host "`n`n`n"
}

sleep(1)
if ((get-childitem -force 'c:\programdata\microsoft\windows\start menu\programs\startup').count -gt 1){
    $misconfigCount++
    Write-Host "$misconfigCount`. Additional Items in C:\ProgramData\Microsoft\Windows\Start Menu\programs\startup" -ForegroundColor Yellow
    Write-Host "`n`t" (get-childitem -force 'c:\programdata\microsoft\windows\start menu\programs\startup' | ?{$_.name -ne 'desktop.ini'}).name -ForegroundColor Yellow
    Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
    Write-Host "`t`t- Could be used so that malware can persist." -ForegroundColor Gray
    Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
    Write-Host "`n`n`n"
}

sleep(1)

if ((gci $PSHome | ? {$_.name -like "*profile.ps1"}) ){
    $misconfigCount++
    Write-Host "$misconfigCount`. $PSHOME\Profile.ps1 has been changed." -ForegroundColor Yellow   
    Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
    Write-Host "`t`t- This file can be used to execute malware when Powershell.exe is executed." -ForegroundColor Gray
    Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
    Write-Host "`n`t`t`t`t`t Check $PSHOME\Profile.ps1." -ForegroundColor Gray
    Write-Host "`n`n`n"
}

sleep(1)

if ( (($env:path | out-string).split(";")).count -gt 6){
    $misconfigCount++
    Write-Host "$misconfigCount`. The Path environmental variable has been changed." -ForegroundColor Yellow
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

sleep(1)

if (((get-item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' | out-string) -split "`n" | select-string Userinit | out-string).replace("Userinit                     :","").trim() -ne "C:\Windows\system32\userinit.exe,"){
    $misconfigCount++
    Write-Host "$misconfigCount`. Potential Threat found in the UserInit Registry value." -ForegroundColor Yellow
    Write-Host "`n`tDefault USERINIT value for Windows: C:\Windows\system32\userinit.exe" -ForegroundColor Yellow
    Write-Host "`tActual USERINIT value:"((get-item 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\' | out-string) -split "`n" | select-string Userinit | out-string).replace("Userinit                     :","").trim() -ForegroundColor Yellow
    Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
    Write-Host "`t`t- Artifacts in this value automatically run. Could be used to persist." -ForegroundColor Gray
    Write-Host "`n`t`t`t Course of Action:" -ForegroundColor Gray
    Write-Host "`t`t`t`t - Make sure only userinit.exe is in this value.`n`n`n" -ForegroundColor Gray
}

Write-Host "`n"

sleep(2)

function getScheduledTasksThatStandOut() {


$lisaSchTasks = "OneDrive Standalone Update Task-S-1-5-21-690249082-3703318214-1872523464-1001#\#Ready
.NET Framework NGEN v4.0.30319#\Microsoft\Windows\.NET Framework\#Ready
.NET Framework NGEN v4.0.30319 64#\Microsoft\Windows\.NET Framework\#Ready
.NET Framework NGEN v4.0.30319 64 Critical#\Microsoft\Windows\.NET Framework\#Disabled
.NET Framework NGEN v4.0.30319 Critical#\Microsoft\Windows\.NET Framework\#Disabled
AD RMS Rights Policy Template Management (Automated)#\Microsoft\Windows\Active Directory Rights Management Services Client\#Disabled
AD RMS Rights Policy Template Management (Manual)#\Microsoft\Windows\Active Directory Rights Management Services Client\#Ready
EDP Policy Manager#\Microsoft\Windows\AppID\#Ready
PolicyConverter#\Microsoft\Windows\AppID\#Disabled
VerifiedPublisherCertStoreCheck#\Microsoft\Windows\AppID\#Disabled
Microsoft Compatibility Appraiser#\Microsoft\Windows\Application Experience\#Ready
ProgramDataUpdater#\Microsoft\Windows\Application Experience\#Ready
StartupAppTask#\Microsoft\Windows\Application Experience\#Ready
appuriverifierdaily#\Microsoft\Windows\ApplicationData\#Ready
appuriverifierinstall#\Microsoft\Windows\ApplicationData\#Ready
CleanupTemporaryState#\Microsoft\Windows\ApplicationData\#Ready
DsSvcCleanup#\Microsoft\Windows\ApplicationData\#Ready
Pre-staged app cleanup#\Microsoft\Windows\AppxDeploymentClient\#Disabled
Proxy#\Microsoft\Windows\Autochk\#Ready
BitLocker MDM policy Refresh#\Microsoft\Windows\BitLocker\#Ready
UninstallDeviceTask#\Microsoft\Windows\Bluetooth\#Ready
BgTaskRegistrationMaintenanceTask#\Microsoft\Windows\BrokerInfrastructure\#Ready
AikCertEnrollTask#\Microsoft\Windows\CertificateServicesClient\#Ready
CryptoPolicyTask#\Microsoft\Windows\CertificateServicesClient\#Ready
KeyPreGenTask#\Microsoft\Windows\CertificateServicesClient\#Ready
SystemTask#\Microsoft\Windows\CertificateServicesClient\#Ready
UserTask#\Microsoft\Windows\CertificateServicesClient\#Ready
UserTask-Roam#\Microsoft\Windows\CertificateServicesClient\#Ready
ProactiveScan#\Microsoft\Windows\Chkdsk\#Ready
SyspartRepair#\Microsoft\Windows\Chkdsk\#Ready
License Validation#\Microsoft\Windows\Clip\#Disabled
CreateObjectTask#\Microsoft\Windows\CloudExperienceHost\#Ready
Consolidator#\Microsoft\Windows\Customer Experience Improvement Program\#Ready
UsbCeip#\Microsoft\Windows\Customer Experience Improvement Program\#Ready
Data Integrity Scan#\Microsoft\Windows\Data Integrity Scan\#Ready
Data Integrity Scan for Crash Recovery#\Microsoft\Windows\Data Integrity Scan\#Ready
ScheduledDefrag#\Microsoft\Windows\Defrag\#Ready
Device#\Microsoft\Windows\Device Information\#Ready
Metadata Refresh#\Microsoft\Windows\Device Setup\#Ready
HandleCommand#\Microsoft\Windows\DeviceDirectoryClient\#Ready
HandleWnsCommand#\Microsoft\Windows\DeviceDirectoryClient\#Ready
IntegrityCheck#\Microsoft\Windows\DeviceDirectoryClient\#Disabled
LocateCommandUserSession#\Microsoft\Windows\DeviceDirectoryClient\#Ready
RegisterDeviceAccountChange#\Microsoft\Windows\DeviceDirectoryClient\#Ready
RegisterDeviceLocationRightsChange#\Microsoft\Windows\DeviceDirectoryClient\#Ready
RegisterDevicePeriodic24#\Microsoft\Windows\DeviceDirectoryClient\#Ready
RegisterDevicePolicyChange#\Microsoft\Windows\DeviceDirectoryClient\#Ready
RegisterDeviceProtectionStateChanged#\Microsoft\Windows\DeviceDirectoryClient\#Ready
RegisterDeviceSettingChange#\Microsoft\Windows\DeviceDirectoryClient\#Ready
RegisterDeviceWnsFallback#\Microsoft\Windows\DeviceDirectoryClient\#Ready
RegisterUserDevice#\Microsoft\Windows\DeviceDirectoryClient\#Ready
Scheduled#\Microsoft\Windows\Diagnosis\#Ready
DXGIAdapterCache#\Microsoft\Windows\DirectX\#Ready
SilentCleanup#\Microsoft\Windows\DiskCleanup\#Ready
Microsoft-Windows-DiskDiagnosticDataCollector#\Microsoft\Windows\DiskDiagnostic\#Ready
Microsoft-Windows-DiskDiagnosticResolver#\Microsoft\Windows\DiskDiagnostic\#Disabled
Diagnostics#\Microsoft\Windows\DiskFootprint\#Ready
StorageSense#\Microsoft\Windows\DiskFootprint\#Ready
dusmtask#\Microsoft\Windows\DUSM\#Ready
EDP App Launch Task#\Microsoft\Windows\EDP\#Ready
EDP Auth Task#\Microsoft\Windows\EDP\#Ready
EDP Inaccessible Credentials Task#\Microsoft\Windows\EDP\#Ready
StorageCardEncryption Task#\Microsoft\Windows\EDP\#Ready
ExploitGuard MDM policy Refresh#\Microsoft\Windows\ExploitGuard\#Ready
DmClient#\Microsoft\Windows\Feedback\Siuf\#Ready
DmClientOnScenarioDownload#\Microsoft\Windows\Feedback\Siuf\#Ready
Property Definition Sync#\Microsoft\Windows\File Classification Infrastructure\#Disabled
File History (maintenance mode)#\Microsoft\Windows\FileHistory\#Ready
FODCleanupTask#\Microsoft\Windows\HelloFace\#Ready
ScanForUpdates#\Microsoft\Windows\InstallService\#Ready
ScanForUpdatesAsUser#\Microsoft\Windows\InstallService\#Ready
SmartRetry#\Microsoft\Windows\InstallService\#Ready
WakeUpAndContinueUpdates#\Microsoft\Windows\InstallService\#Disabled
WakeUpAndScanForUpdates#\Microsoft\Windows\InstallService\#Disabled
Installation#\Microsoft\Windows\LanguageComponentsInstaller\#Ready
ReconcileLanguageResources#\Microsoft\Windows\LanguageComponentsInstaller\#Ready
Uninstallation#\Microsoft\Windows\LanguageComponentsInstaller\#Disabled
TempSignedLicenseExchange#\Microsoft\Windows\License Manager\#Ready
Notifications#\Microsoft\Windows\Location\#Ready
WindowsActionDialog#\Microsoft\Windows\Location\#Ready
WinSAT#\Microsoft\Windows\Maintenance\#Ready
Cellular#\Microsoft\Windows\Management\Provisioning\#Ready
Logon#\Microsoft\Windows\Management\Provisioning\#Ready
MapsToastTask#\Microsoft\Windows\Maps\#Ready
MapsUpdateTask#\Microsoft\Windows\Maps\#Disabled
ProcessMemoryDiagnosticEvents#\Microsoft\Windows\MemoryDiagnostic\#Ready
RunFullMemoryDiagnostic#\Microsoft\Windows\MemoryDiagnostic\#Ready
MNO Metadata Parser#\Microsoft\Windows\Mobile Broadband Accounts\#Ready
LPRemove#\Microsoft\Windows\MUI\#Ready
SystemSoundsService#\Microsoft\Windows\Multimedia\#Running
GatherNetworkInfo#\Microsoft\Windows\NetTrace\#Ready
WiFiTask#\Microsoft\Windows\NlaSvc\#Ready
Background Synchronization#\Microsoft\Windows\Offline Files\#Disabled
Logon Synchronization#\Microsoft\Windows\Offline Files\#Disabled
Secure-Boot-Update#\Microsoft\Windows\PI\#Ready
Sqm-Tasks#\Microsoft\Windows\PI\#Ready
Device Install Group Policy#\Microsoft\Windows\Plug and Play\#Ready
Device Install Reboot Required#\Microsoft\Windows\Plug and Play\#Ready
Sysprep Generalize Drivers#\Microsoft\Windows\Plug and Play\#Ready
AnalyzeSystem#\Microsoft\Windows\Power Efficiency Diagnostics\#Ready
EduPrintProv#\Microsoft\Windows\Printing\#Ready
LoginCheck#\Microsoft\Windows\PushToInstall\#Disabled
Registration#\Microsoft\Windows\PushToInstall\#Ready
MobilityManager#\Microsoft\Windows\Ras\#Ready
VerifyWinRE#\Microsoft\Windows\RecoveryEnvironment\#Disabled
RegIdleBackup#\Microsoft\Windows\Registry\#Ready
RemoteAssistanceTask#\Microsoft\Windows\RemoteAssistance\#Ready
shell#\Microsoft\Windows\rempl\#Ready
StartComponentCleanup#\Microsoft\Windows\Servicing\#Ready
BackgroundUploadTask#\Microsoft\Windows\SettingSync\#Ready
NetworkStateChangeTask#\Microsoft\Windows\SettingSync\#Ready
Account Cleanup#\Microsoft\Windows\SharedPC\#Disabled
CreateObjectTask#\Microsoft\Windows\Shell\#Ready
FamilySafetyMonitor#\Microsoft\Windows\Shell\#Ready
FamilySafetyMonitorToastTask#\Microsoft\Windows\Shell\#Disabled
FamilySafetyRefreshTask#\Microsoft\Windows\Shell\#Ready
IndexerAutomaticMaintenance#\Microsoft\Windows\Shell\#Ready
SvcRestartTask#\Microsoft\Windows\SoftwareProtectionPlatform\#Ready
SvcRestartTaskLogon#\Microsoft\Windows\SoftwareProtectionPlatform\#Ready
SvcRestartTaskNetwork#\Microsoft\Windows\SoftwareProtectionPlatform\#Ready
SpaceAgentTask#\Microsoft\Windows\SpacePort\#Ready
SpaceManagerTask#\Microsoft\Windows\SpacePort\#Ready
HeadsetButtonPress#\Microsoft\Windows\Speech\#Ready
SpeechModelDownloadTask#\Microsoft\Windows\Speech\#Ready
Storage Tiers Management Initialization#\Microsoft\Windows\Storage Tiers Management\#Ready
Storage Tiers Optimization#\Microsoft\Windows\Storage Tiers Management\#Disabled
EnableLicenseAcquisition#\Microsoft\Windows\Subscription\#Ready
LicenseAcquisition#\Microsoft\Windows\Subscription\#Disabled
HybridDriveCachePrepopulate#\Microsoft\Windows\Sysmain\#Disabled
HybridDriveCacheRebalance#\Microsoft\Windows\Sysmain\#Disabled
ResPriStaticDbSync#\Microsoft\Windows\Sysmain\#Ready
WsSwapAssessmentTask#\Microsoft\Windows\Sysmain\#Ready
SR#\Microsoft\Windows\SystemRestore\#Ready
Interactive#\Microsoft\Windows\Task Manager\#Ready
MsCtfMonitor#\Microsoft\Windows\TextServicesFramework\#Ready
ForceSynchronizeTime#\Microsoft\Windows\Time Synchronization\#Ready
SynchronizeTime#\Microsoft\Windows\Time Synchronization\#Ready
SynchronizeTimeZone#\Microsoft\Windows\Time Zone\#Ready
Tpm-HASCertRetr#\Microsoft\Windows\TPM\#Ready
Tpm-Maintenance#\Microsoft\Windows\TPM\#Ready
RunUpdateNotificationMgr#\Microsoft\Windows\UNP\#Disabled
Maintenance Install#\Microsoft\Windows\UpdateOrchestrator\#Disabled
MusUx_LogonUpdateResults#\Microsoft\Windows\UpdateOrchestrator\#Ready
Reboot#\Microsoft\Windows\UpdateOrchestrator\#Ready
Schedule Scan#\Microsoft\Windows\UpdateOrchestrator\#Ready
USO_Broker_Display#\Microsoft\Windows\UpdateOrchestrator\#Ready
UPnPHostConfig#\Microsoft\Windows\UPnP\#Ready
Usb-Notifications#\Microsoft\Windows\USB\#Ready
HiveUploadTask#\Microsoft\Windows\User Profile Service\#Disabled
PerformRemediation#\Microsoft\Windows\WaaSMedic\#Disabled
WiFiTask#\Microsoft\Windows\WCM\#Ready
ResolutionHost#\Microsoft\Windows\WDI\#Running
Windows Defender Cache Maintenance#\Microsoft\Windows\Windows Defender\#Ready
Windows Defender Cleanup#\Microsoft\Windows\Windows Defender\#Ready
Windows Defender Scheduled Scan#\Microsoft\Windows\Windows Defender\#Ready
Windows Defender Verification#\Microsoft\Windows\Windows Defender\#Ready
QueueReporting#\Microsoft\Windows\Windows Error Reporting\#Ready
BfeOnServiceStartTypeChange#\Microsoft\Windows\Windows Filtering Platform\#Ready
UpdateLibrary#\Microsoft\Windows\Windows Media Sharing\#Ready
Calibration Loader#\Microsoft\Windows\WindowsColorSystem\#Ready
Scheduled Start#\Microsoft\Windows\WindowsUpdate\#Ready
sih#\Microsoft\Windows\WindowsUpdate\#Ready
CacheTask#\Microsoft\Windows\Wininet\#Running
WIM-Hash-Management#\Microsoft\Windows\WOF\#Ready
WIM-Hash-Validation#\Microsoft\Windows\WOF\#Disabled
Work Folders Logon Synchronization#\Microsoft\Windows\Work Folders\#Ready
Work Folders Maintenance Work#\Microsoft\Windows\Work Folders\#Ready
Automatic-Device-Join#\Microsoft\Windows\Workplace Join\#Disabled
Recovery-Check#\Microsoft\Windows\Workplace Join\#Disabled
NotificationTask#\Microsoft\Windows\WwanSvc\#Ready
XblGameSaveTask#\Microsoft\XblGameSave\#Ready
AD RMS Rights Policy Template Management (Automated)#\Microsoft\Windows\Active Directory Rights Management Services Client\#Disabled
AD RMS Rights Policy Template Management (Manual)#\Microsoft\Windows\Active Directory Rights Management Services Client\#Ready
File History (maintenance mode)#\Microsoft\Windows\FileHistory\#Ready"

Write-Host "Checking scheduled tasks...`n" -ForegroundColor Green

sleep(3)

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
                        $misconfigCount++
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
            $misconfigCount++
            Write-Host "$misconfigCount`. Additional Task Found in Scheduled Tasks." -Foregroundcolor Yellow
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

function getProcessesThatStandOut(){
$lisaProcesses = "ApplicationFrameHost#C:\Windows\system32\ApplicationFrameHost.exe
backgroundTaskHost#C:\Windows\system32\backgroundTaskHost.exe
backgroundTaskHost#C:\Windows\system32\backgroundTaskHost.exe
csrss#
csrss#
ctfmon#
dllhost#C:\Windows\system32\DllHost.exe
dllhost#C:\Windows\system32\DllHost.exe
dllhost#C:\Windows\system32\DllHost.exe
dwm#
explorer#C:\Windows\Explorer.EXE
fontdrvhost#
fontdrvhost#
Idle#
lsass#
Memory Compression#
MSASCuiL#C:\Program Files\Windows Defender\MSASCuiL.exe
MsMpEng#
NisSrv#
OneDrive#C:\Users\terry\AppData\Local\Microsoft\OneDrive\OneDrive.exe
powershell_ise#C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe
Registry#
rundll32#C:\Windows\system32\rundll32.exe
RuntimeBroker#C:\Windows\System32\RuntimeBroker.exe
RuntimeBroker#C:\Windows\System32\RuntimeBroker.exe
RuntimeBroker#C:\Windows\System32\RuntimeBroker.exe
RuntimeBroker#C:\Windows\System32\RuntimeBroker.exe
RuntimeBroker#C:\Windows\System32\RuntimeBroker.exe
RuntimeBroker#C:\Windows\System32\RuntimeBroker.exe
SearchFilterHost#
SearchIndexer#
SearchProtocolHost#
SearchUI#C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe
SecurityHealthService#
services#
SettingSyncHost#C:\Windows\system32\SettingSyncHost.exe
SgrmBroker#
ShellExperienceHost#C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe
sihost#C:\Windows\System32\sihost.exe
smartscreen#C:\Windows\System32\smartscreen.exe
smss#
spoolsv#
svchost#
svchost#
svchost#
svchost#
svchost#
svchost#
svchost#
svchost#
svchost#
svchost#
svchost#
svchost#
svchost#
svchost#
svchost#
svchost#
svchost#C:\Windows\system32\svchost.exe
svchost#
svchost#
svchost#
svchost#
System#
taskhostw#C:\Windows\System32\taskhostw.exe
wininit#
winlogon#
WmiPrvSE#
WmiPrvSE#"

$lisaProcesses = $lisaProcesses.Trim()

    Write-Host "Checking processes...`n" -ForegroundColor Green
    sleep(5)
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
                    
                    if ($path -ne $line.split("#")[1]){
                        $misconfigCount++
                        Write-Host "$misconfigCount`. Process running from wrong location!"
                        Write-Host "Process: $name" -ForegroundColor Yellow
                        Write-Host "Correct Location: $correctlocation `nActual Location: $path" -ForegroundColor Yellow
                        Write-Host "`n`tWhy is this a potential threat?`n" -ForegroundColor Gray
                        Write-Host "`n`tTrojans typically mimic legitimate processes by name but run from incorrect locations." -ForegrounColor Gray
                        Write-Host "`t`t- Malicious running processes are used as means of persistence and should be killed/removed." -ForegroundColor Gray
                        Write-Host "`n`t`t`t`t Course of Action:" -ForegroundColor Gray
                        Write-Host "`n`t`t`t`t`t Ensure that this process does not belong to legitimate applications or the Windows environment." -ForegroundColor Gray
                        Write-Host "`n`t`t`t`t`t Remove process immediately if this process is not being used legitimately." -ForegroundColor Gray
                        Write-Host "`n`n`n"
                        $noUnknownProcesses = $false


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


getScheduledTasksThatStandOut

getProcessesThatStandOut
$misconfigCount++
Write-Host "`n`n`nTOTAL NUMBER OF MISCONFIGURATIONS FOUND:`t$misconfigCount" -ForegroundColor Cyan

<#

    get-item hkcu:\software\microsoft\internet explorer\typedurls

#>
