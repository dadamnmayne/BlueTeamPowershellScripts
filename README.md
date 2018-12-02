# BlueTeamPowershellScripts
A collection of self-made Powershell Scripts for Cyber Security Host Analysts


get-PersistenceItems.ps1


This script "knows normal". It scans any box and compares it to the artifacts of a normal box.
It contains strings saved in variables known as LISAs.
A LISA is a string of artifacts from a clean Windows image that has never been connected to the internet.
This script has "LISA scheduled tasks", "LISA registry keys", and "LISA running processes"
You no longer have to memorize which scheduled tasks are normal or which processes are normal.
This script does this for you.

![alt text](https://github.com/TerrySmithMBA/BlueTeamPowershellScripts/blob/master/get-ProcessesThatStandOut/get-processesThatStandOut.PNG)

[Microsoft Add-In is malicious; the last two tasks are potentially malicious]

![alt text](https://github.com/TerrySmithMBA/BlueTeamPowershellScripts/blob/master/get-ScheduledTasksThatStandOut/getSchTasks.PNG)
