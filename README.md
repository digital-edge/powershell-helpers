# A collection of useful powershell scripts

Get-HotfixStatus 
----------------
This script checks if a hotfix is installed on a list of computers. You can specify a list of computers in a text file or an IP range in a CIDR format. You can specify a hotfix or a list of hotfixes. The script will get some extra information from the scanned host such as host name and OS.

Examples:

```
 .\Get-HotfixStatus.ps1 -Hotfixes KB4499164 -Computers TESTPC1,192.168.1.0/24

 .\Get-HotfixStatus.ps1 -Hotfixes KB4499164 -Computers 192.168.1.0/24

 .\Get-HotfixStatus.ps1 -Hotfixes KB4499164,KB3011780 -ComputersFile Computers.txt | Out-GridView

 .\Get-HotfixStatus.ps1 -Hotfixes KB4499164,KB3011780 -ComputersFile Computers.txt | Export-Csv Report.csv -NoTypeInformation

```
