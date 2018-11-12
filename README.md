# BlueTeamPowershellScripts
A collection of self-made Powershell Scripts for Cyber Security Host Analysts

get-ProcessesThatStandOut.ps1

Will look over processes to see if they are running in their correct locations. If not, the script will inform you.
Also, will look over processes that are not running on a freshly-installed and freshly-booted Windows 10 image.
  If the processes would not be running on a fresh image with no user interaction, the process pops up as: Additional Process Running.

    
    o SVCHOST should run out of system32, but since it is not, the script alerts the user. 
    Notice, it also displays the parent process.
      Process: svchost
      Correct Location: c:\windows\system32\svchost.exe 
      Actual Location: c:\users\badguy\downloads\svchost.exe
      svchost in wrong location!
      Parent Process: bad.exe
    
    o These processes are native to Windows, but since they don't run after a fresh install and a fresh boot with no internet connectivity, they appear in the output of the script.

      Additional Process Running: Windows.WARP.JITService
      Start time: 11/09/2018 16:13:59
      No company information given
      Additional Process Running: Windows.WARP.JITService
      Start time: 11/09/2018 16:23:03
      No company information given


