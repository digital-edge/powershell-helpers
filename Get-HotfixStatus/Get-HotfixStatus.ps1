#requires -version 2
<#
.SYNOPSIS
  This script checks if a hotfix is installed on a list of computers.
.DESCRIPTION
  This script checks if a hotfix is installed on a list of computers. 
  You can specify a list of computers in a text file or an IP range in a CIDR format.
  You can specify a hotfix or a list of hotfixes. 
  The script will get some extra information from the scanned host such as host name and OS.
.PARAMETER Hotfixes
  Specify the hotfix or a comma separated list of hotfixes to check.
.PARAMETER Computers
  Specify a computer, a comma separated list of computers or an IP range to check.
.PARAMETER ComputersFile
  Specify a path to a text file with the list of computer names or IPs.
.INPUTS
  None
.OUTPUTS
  The list of computers and patch information.
.NOTES
  Version:        1.0
  Author:         Digital Edge 
  Creation Date:  5/18/2019
  Purpose/Change: Initial script development
.EXAMPLE
  .\Get-HotfixStatus.ps1 -Hotfixes KB4499164 -Computers TESTPC1,192.168.1.0/24
.EXAMPLE
  .\Get-HotfixStatus.ps1 -Hotfixes KB4499164 -Computers 192.168.1.0/24
.EXAMPLE
  .\Get-HotfixStatus.ps1 -Hotfixes KB4499164,KB3011780 -ComputersFile Computers.txt | Out-GridView
.EXAMPLE
  .\Get-HotfixStatus.ps1 -Hotfixes KB4499164,KB3011780 -ComputersFile Computers.txt | Export-Csv Report.csv -NoTypeInformation
#>

#---------------------------------------------------------[Script Parameters]------------------------------------------------------

[CmdletBinding(DefaultParameterSetName = 'FromName')]
param(
  [Parameter(Mandatory = $true)]
  [string[]]
  $Hotfixes,

  [Parameter(Mandatory = $true,ParameterSetName = 'FromName')]
  [string[]]
  $Computers,

  [Parameter(Mandatory = $true,ParameterSetName = 'FromFile')]
  [string]
  $ComputersFile
)


#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Set Error Action to Silently Continue
$ErrorActionPreference = "SilentlyContinue"

#----------------------------------------------------------[Declarations]----------------------------------------------------------


#-----------------------------------------------------------[Functions]------------------------------------------------------------

function New-IPv4toBin ($ipv4)
{
  # IP to Binary
  $BinNum = $ipv4 -split '\.' | ForEach-Object { [System.Convert]::ToString($_,2).PadLeft(8,'0') }
  return $binNum -join ""
}

function Get-Broadcast ($addressAndCidr)
{
  # Get Broadcast Address From Cird
  $addressAndCidr = $addressAndCidr.Split("/")
  $addressInBin = (New-IPv4toBin $addressAndCidr[0]).ToCharArray()
  for ($i = 0; $i -lt $addressInBin.length; $i++)
  {
    if ($i -ge $addressAndCidr[1])
    {
      $addressInBin[$i] = "1"
    }
  }
  [string[]]$addressInInt32 = @()
  for ($i = 0; $i -lt $addressInBin.length; $i++)
  {
    $partAddressInBin += $addressInBin[$i]
    if (($i + 1) % 8 -eq 0)
    {
      $partAddressInBin = $partAddressInBin -join ""
      $addressInInt32 += [Convert]::ToInt32($partAddressInBin -join "",2)
      $partAddressInBin = ""
    }
  }
  $addressInInt32 = $addressInInt32 -join "."
  return $addressInInt32
}

function New-IPRange ($start,$end)
{
  # Create IP range array
  $ip1 = ([System.Net.IPAddress]$start).GetAddressBytes()
  [array]::Reverse($ip1)
  $ip1 = ([System.Net.IPAddress]($ip1 -join '.')).Address
  $ip2 = ([System.Net.IPAddress]$end).GetAddressBytes()

  [array]::Reverse($ip2)
  $ip2 = ([System.Net.IPAddress]($ip2 -join '.')).Address

  for ($addres = $ip1; $addres -le $ip2; $addres++)
  {
    $ip = ([System.Net.IPAddress]$addres).GetAddressBytes()
    [array]::Reverse($ip)
    $ip -join '.'
  }
}

function GetStatusCode
{
  # Expand ping status code

  param([int]$StatusCode)
  switch ($StatusCode)
  {
    0 { "Success" }
    11001 { "Buffer Too Small" }
    11002 { "Destination Net Unreachable" }
    11003 { "Destination Host Unreachable" }
    11004 { "Destination Protocol Unreachable" }
    11005 { "Destination Port Unreachable" }
    11006 { "No Resources" }
    11007 { "Bad Option" }
    11008 { "Hardware Error" }
    11009 { "Packet Too Big" }
    11010 { "Request Timed Out" }
    11011 { "Bad Request" }
    11012 { "Bad Route" }
    11013 { "TimeToLive Expired Transit" }
    11014 { "TimeToLive Expired Reassembly" }
    11015 { "Parameter Problem" }
    11016 { "Source Quench" }
    11017 { "Option Too Big" }
    11018 { "Bad Destination" }
    11032 { "Negotiating IPSEC" }
    11050 { "General Failure" }
    default { "Failed" }
  }
}


#-----------------------------------------------------------[Execution]------------------------------------------------------------


# Turn input variables into two arrays hotfixes and computers

# Hotfixes

# If just one hotfix specified
if ($Hotfixes -isnot [System.Array])
{
  # Turn hotfixes into an array with 1 element 
  $Hotfixes = @($Hotfixes)
}



# Computers

# If loading from file
if ($PSCmdlet.ParameterSetName -eq "FromFile")
{

  # Check if file exists
  if (Test-Path -Path $ComputersFile)
  {
    # File exists

    # Create empty array
    $Computers = [System.Collections.ArrayList]@()

    # Read file line by line
    foreach ($line in Get-Content -Path $ComputersFile)
    {
      $Computer = $line.Trim()
      if ($Computer -ne "")
      {
        # Add to array if not an empty string
        $Computers += $Computer
      }
    }

    # Check if any elements in the array now
    if ($Computers.Count -eq 0)
    {
      Write-Host -ForegroundColor Red "ERROR: File $ComputersFile does not contain any computer names, exiting."
      exit
    }
  }
  else {

    # File doesn't exist

    Write-Host -ForegroundColor Red "ERROR: File $ComputersFile is not found, exiting."
    exit

  }
}
else {
  # Loading from variable

  # Check if only one computer specified
  if ($Computers -isnot [System.Array])
  {
    # Turn Computers into an array with 1 element 
    $Computers = @($Computers)
  }
}


# Now let's expand thouse CIDRs
$TempComputers = $Computers
$Computers = [System.Collections.ArrayList]@()


foreach ($Computer in $TempComputers)
{
  # Check if it's a CIDR
  if ($Computer -like "*.*.*.*/*")
  {
    # It is CIDR
    ($IP,$Mask) = $Computer.Split("/")

    # Calculate the range and add all IPs to the array
    $Computers += (New-IPRange $IP (Get-Broadcast "$IP/$Mask"))
  }
  else {
    # It's computer name or a single IP, just add to the array.
    $Computers += $Computer
  }
}


# Let's go through our computers one by one

foreach ($Computer in $Computers)
{

  # Will be true if any WMI stuff fails
  $pcnotfound = "false"

  try {

    # Get Ping object via WMI
    $pingStatus = Get-WmiObject -Query "Select * from win32_PingStatus where Address='$Computer'"

    if ($pingStatus.StatusCode -eq 0)
    {
      $Status = GetStatusCode ($pingStatus.StatusCode)
    }
    else
    {
      $Status = GetStatusCode ($pingStatus.StatusCode)
    }

    # Get OS object via WMI
    $OS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer
    $name = $OS.CSName
    $OSRunning = $OS.caption + " " + $OS.OSArchitecture + " (" + $OS.Version + ")"
    $uptime = $OS.ConvertToDateTime($OS.lastbootuptime)

  }

  catch
  {
    # In case of any WMI issues, mark computer as not found
    $pcnotfound = "true"
  }


  # Check if computer is found
  if ($pcnotfound -eq "true")
  {
    # Computer is not found

    # Create output object
    $Object = New-Object PSObject -Property @{
      Computer = $computer
      Status = $Status
      Name = "Not Found"
      OS = $null
      Uptime = $null
    }

    # Add hotfix columns
    foreach ($Hotfix in $Hotfixes)
    {
      $Object | Add-Member $Hotfix "N/A"
    }

    # Output (can be formatted and piped to different output formats)
    $Object | Select-Object Computer,Status,Name,OS,Uptime,*
  }
  else
  {
    # Computer is found

    # Create output object
    $Object = New-Object PSObject -Property @{
      Computer = $computer
      Status = $status
      Name = $name
      OS = $OSRunning
      Uptime = $uptime
    }

    # Go throug each hotfix
    foreach ($Hotfix in $Hotfixes)
    {

      # Check if hotfix is installed
      if (Get-HotFix -Id $Hotfix -ComputerName $computer | Out-Null)
      {
        $kbinstall = "Installed"
      }
      else
      {
        $kbinstall = "Not Installed"
      }

      # Add hotfix column to the output object
      $Object | Add-Member $Hotfix $kbinstall
    }

    # Output (can be formatted and piped to different output formates)
    $Object | Select-Object Computer,Status,Name,OS,Uptime,*
  }

}
