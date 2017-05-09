################################################################################
# https://msdn.microsoft.com/en-us/library/aa389752(v=vs.85).aspx
################################################################################
$Provider = "CIMWIN32"
#$Name = "CreateProcessWithLogonW"
$ClassName = "Win32_ProcLog"
$MethodName = "Create"
################################################################################
################################################################################
$__PARAMETERS = New-Object System.Management.ManagementClass("ROOT", "__PARAMETERS", $null)
################################################################################
################################################################################
$InParameters = $__PARAMETERS.Clone()
$InParameters.Qualifiers.Add("In", $false)

$InParameters.Properties.Add("CommandLine", [System.Management.CimType]::String, $false)
$InParameters.Properties["CommandLine"].Qualifiers.Add("In", $false)
$InParameters.Properties["CommandLine"].Qualifiers.Add("ID", 0, $false, $true, $false, $false)
$InParameters.Properties["CommandLine"].Qualifiers.Add("MappingStrings", [String[]]"Win32API|Process and Thread Functions|lpCommandLine ")

$InParameters.Properties.Add("CurrentDirectory", [System.Management.CimType]::String, $false)
$InParameters.Properties["CurrentDirectory"].Qualifiers.Add("In", $false)
$InParameters.Properties["CurrentDirectory"].Qualifiers.Add("ID", 1, $false, $true, $false, $false)
$InParameters.Properties["CurrentDirectory"].Qualifiers.Add("MappingStrings", [String[]]"Win32API|Process and Thread Functions|CreateProcess|lpCurrentDirectory ")

$InParameters.Properties.Add("ProcessStartupInformation", [System.Management.CimType]::Object, $false)
$InParameters.Properties["ProcessStartupInformation"].Qualifiers.Add("CIMTYPE", "object:Win32_ProcessStartup")
$InParameters.Properties["ProcessStartupInformation"].Qualifiers.Add("In", $true)
$InParameters.Properties["ProcessStartupInformation"].Qualifiers.Add("ID", 2, $false, $true, $false, $false)
$InParameters.Properties["ProcessStartupInformation"].Qualifiers.Add("MappingStrings", [String[]]"WMI|Win32_ProcessStartup")
$InParameters.Properties["ProcessStartupInformation"].Qualifiers.Add("EmbeddedInstance", "Win32_ProcessStartup")

$TempPtr = [System.IntPtr]$InParameters
$DotNetPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
$SystemManagement = [System.Reflection.Assembly]::LoadFile($DotNetPath+"System.Management.dll")
$IWbemClassObjectFreeThreaded = $SystemManagement.GetType(‘System.Management.IWbemClassObjectFreeThreaded’)
$IWbemClassObjectFreeThreaded_ctor = $IWbemClassObjectFreeThreaded.GetConstructors()[0]
$IWbemClassObjectFreeThreadedInstance = $IWbemClassObjectFreeThreaded_ctor.Invoke($TempPtr)
$ManagementBaseObject = $SystemManagement.GetType(‘System.Management.ManagementBaseObject’)
$ManagementBaseObject_ctor = $ManagementBaseObject.GetConstructors([Reflection.BindingFlags] "NonPublic, Instance")[1]
$InParametersManagementBaseObjectInstance = $ManagementBaseObject_ctor.Invoke($IWbemClassObjectFreeThreadedInstance)
################################################################################
################################################################################
$OutParameters =$__PARAMETERS.Clone()
$OutParameters.Qualifiers.Add("Out", $false)

$OutParameters.Properties.Add("ProcessId", [System.Management.CimType]::UInt32, $false)
$OutParameters.Properties["ProcessId"].Qualifiers.Add("Out", $false)
$OutParameters.Properties["ProcessId"].Qualifiers.Add("ID", 3, $false, $true, $false, $false)
$OutParameters.Properties["ProcessId"].Qualifiers.Add("MappingStrings", [String[]]"Win32API|Process and Thread Functions|CreateProcess|lpProcessInformation|dwProcessId")

$OutParameters.Properties.Add("ReturnValue", [System.Management.CimType]::UInt32, $false)
$OutParameters.Properties["ReturnValue"].Qualifiers.Add("Out", $true)

$TempPtr = [System.IntPtr]$OutParameters
$DotNetPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
$SystemManagement = [System.Reflection.Assembly]::LoadFile($DotNetPath+"System.Management.dll")
$IWbemClassObjectFreeThreaded = $SystemManagement.GetType(‘System.Management.IWbemClassObjectFreeThreaded’)
$IWbemClassObjectFreeThreaded_ctor = $IWbemClassObjectFreeThreaded.GetConstructors()[0]
$IWbemClassObjectFreeThreadedInstance = $IWbemClassObjectFreeThreaded_ctor.Invoke($TempPtr)
$ManagementBaseObject = $SystemManagement.GetType(‘System.Management.ManagementBaseObject’)
$ManagementBaseObject_ctor = $ManagementBaseObject.GetConstructors([Reflection.BindingFlags] "NonPublic, Instance")[1]
$OutParametersManagementBaseObjectInstance = $ManagementBaseObject_ctor.Invoke($IWbemClassObjectFreeThreadedInstance)
################################################################################
################################################################################
$CIMProcess = New-Object System.Management.ManagementClass("ROOT\CIMv2", "CIM_Process", $null)
$Class = $CIMProcess.Derive($ClassName)

$Class.Qualifiers.Add("dynamic", $true, $false, $true, $false, $true)
$Class.Qualifiers.Add("provider", $Provider, $false, $true, $false, $true)
$Class.Qualifiers.Add("SupportsCreate", $true)
$Class.Qualifiers.Add("CreateBy", "Create")
$Class.Qualifiers.Add("SupportsDelete", $true)
$Class.Qualifiers.Add("DeleteBy", "DeleteInstance")
$Class.Qualifiers.Add("Locale", 1033, $false, $true, $false, $true)
$Class.Qualifiers.Add("UUID", "{8503C4DC-5FBB-11D2-AAC1-006008C78BC7}", $false, $true, $false, $true)
$Class.Methods.Add($MethodName, $InParametersManagementBaseObjectInstance, $OutParametersManagementBaseObjectInstance)
$Class.Methods["$MethodName"].Qualifiers.Add("Constructor", $true)
$Class.Methods["$MethodName"].Qualifiers.Add("Static", $true)
$Class.Methods["$MethodName"].Qualifiers.Add("Implemented", $true)
$Class.Methods["$MethodName"].Qualifiers.Add("Privileges", [String[]]@("SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege", "SeRestorePrivilege"), $false, $false, $true, $true)
$Class.Methods["$MethodName"].Qualifiers.Add("ValueMap", [String[]]@("0", "2", "3", "8", "9", "21", ".."), $false, $false, $true, $true)
$Class.Methods["$MethodName"].Qualifiers.Add("MappingStrings", [String[]]"Win32API|Process and Thread Functions|CreateProcess", $false, $false, $true, $true)
################################################################################
################################################################################
$Class.Properties.Add("ProcessId", [System.Management.CimType]::UInt32, $false)
$Class.Properties["ProcessId"].Qualifiers.Add("read", $true, $false, $false, $true, $true)
$Class.Properties["ProcessId"].Qualifiers.Add("MappingStrings", [String[]]"Win32API|Process and Thread Structures|PROCESS_INFORMATION|dwProcessId ", $false, $false, $true, $true)

$Class.Properties.Add("CommandLine", [System.Management.CimType]::String, $false)
$Class.Properties["ProcessId"].Qualifiers.Add("read", $true)

Remove-WmiObject -Class $ClassName

$Class.Put()

Get-CimClass -ClassName $ClassName

Get-WmiObject -Class $ClassName

Invoke-WmiMethod -Class $ClassName -Name $MethodName -ArgumentList notepad.exe

(Get-WmiObject -List -Class $ClassName).Qualifiers | FT -Force
(Get-WmiObject -List -Class Win32_Process).Qualifiers | FT -Force

(Get-WmiObject -List -Class $ClassName).Properties | ? IsLocal -NE True | FT -Force
(Get-WmiObject -List -Class Win32_Process).Properties | ? IsLocal -NE True | FT -Force

(Get-CimClass $ClassName).CimClassQualifiers | FT -Force
(Get-CimClass Win32_Process).CimClassQualifiers | FT -Force
Write-Warning "a" 
(Get-CimClass $ClassName).CimClassMethods | FT -Force
Write-Warning "b" 
(Get-CimClass $ClassName).CimClassProperties | FT -Force
################################################################################
################################################################################
Function local:Get-ManagementBaseObject {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [Object]$Class
    )
    $TempPtr = [System.IntPtr]$Class
    $DotNetPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
    $SystemManagement = [System.Reflection.Assembly]::LoadFile($DotNetPath+"System.Management.dll")

    $IWbemClassObjectFreeThreaded = $SystemManagement.GetType(‘System.Management.IWbemClassObjectFreeThreaded’)
    $IWbemClassObjectFreeThreaded_ctor = $IWbemClassObjectFreeThreaded.GetConstructors()[0]
    $IWbemClassObjectFreeThreadedInstance = $IWbemClassObjectFreeThreaded_ctor.Invoke($TempPtr)

    $ManagementBaseObject = $SystemManagement.GetType(‘System.Management.ManagementBaseObject’)
    $ManagementBaseObject_ctor = $ManagementBaseObject.GetConstructors([Reflection.BindingFlags] "NonPublic, Instance")[1]
    $ManagementBaseObjectInstance = $ManagementBaseObject_ctor.Invoke($IWbemClassObjectFreeThreadedInstance)

    Return $ManagementBaseObjectInstance
}
################################################################################
################################################################################
Function local:Invoke-ProviderSetup {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [Object]$Class
    )
    $__Win32Provider = Set-WmiInstance -Class __Win32Provider -Arguments @{
        Name = $Provider;
        ClsId = "{d63a5850-8f16-11cf-9f47-00aa00bf345c}";
        ImpersonationLevel = 1;
        PerUserInitialization = "FALSE";
        HostingModel = "NetworkServiceHost";
        }

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
################################################################################
Function local:Invoke-NotInstallUtil {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [string]$file
    )
    #The powershell version needs to match the installing dll version
    Unblock-File $file
    [System.Configuration.Install.ManagedInstallerClass]::InstallHelper(@($file))
}
<#
################################################################################
################################################################################
$QualifierData = $SystemManagement.GetType(‘System.Management.QualifierData’)
$QualifierData_ctor = $QualifierData.GetType().GetConstructors([Reflection.BindingFlags] "NonPublic, Instance")
#>
