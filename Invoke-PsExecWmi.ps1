<#
    $pass = ConvertTo-SecureString “Password” -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential (“username”, $pass)
#>
################################################################################
# Add MaxEnvelopeSize 
# Add Exe file Copying
################################################################################

Function Invoke-PsExecWmi {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage=".")]
            [string]$ComputerName,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [pscredential]$Credential,
        [Parameter(Mandatory=$true, HelpMessage=".")]
            [string]$Command,
        [Parameter(Mandatory=$true, HelpMessage=".")]
            [string]$File,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [switch]$PowerShellWrite,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [switch]$BatchWrite,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [switch]$ServicePathFolder = "C:\Windows\temp"
    )

    Begin {
        Write-Verbose "Opening CimSession"
        $CimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential

        $errorControl = [byte] 1
        $serviceType = [byte] 16
        $Random = -join ((65..90) + (97..122) | Get-Random -Count 16 | % {[char]$_})
        Write-Verbose "Using FileName $Random"

        if ($PowerShellWrite) {
            $PsCommand = "powershell.exe -V 2 -NoP -NoL -NonI -W Hidden -Command Set-Content -Path C:\Windows\temp\$random.bat -Value `'$payload`'"
        } elseif ($BatchWrite) {
            $CmdCommand = "cmd.exe /c echo $Payload > C:\Windows\temp\$Random.bat"
        }
    } Process {
        Write-Verbose "Creating Remote File $ServicePath\$Random.bat"
        Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
            CommandLine = $PsCommand
        } -CimSession $CimSession
        Write-Verbose "Creating Remote Service $Random"
        $Service = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
            DesktopInteract = $false
            DisplayName = $Random
            ErrorControl = $errorControl
            Name = $Random
            PathName = "cmd.exe /c start /b $ServicePath\$Random.bat"
            ServiceType = $serviceType
            StartMode = "Manual"
            StartName = "NT AUTHORITY\SYSTEM"
            StartPassword = ""
        } -CimSession $CimSession

        $Service = Get-CimInstance -ClassName Win32_Service -Filter "Name = '$Random'"
        Write-Verbose "Starting Service"
        $Service | Invoke-CIMMethod -Name StartService
    } End {
        Write-Verbose "Stoping Service"
        $Service | Invoke-CIMMethod -Name StopService
        Write-Verbose "Deleting Service"
        $Service | Invoke-CIMMethod -Name Delete
        Write-Verbose "Deleting File"
        $File = Get-CimInstance -Query "SELECT * FROM CIM_DataFile WHERE Name = 'C:\\Windows\\temp\\$Random.bat'" -CimSession $CimSession
        $File.Delete()
    }
}