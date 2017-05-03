################################################################################
# https://msdn.microsoft.com/en-us/library/aa389752(v=vs.85).aspx
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
#$Name = "CreateProcessWithLogonW"
$Name = "Create"

$CIMProcess = New-Object System.Management.ManagementClass("ROOT\CIMv2", "CIM_Process", $null)
$Class = $CIMProcess.Derive("Win32_ProcessLogon")

$Class.Qualifiers.Add("dynamic", $true)
$Class.Qualifiers.Add("provider", "CIMWin32", $false, $true, $false, $true)
$Class.Qualifiers.Add("SupportsCreate", $true)
$Class.Qualifiers.Add("CreateBy", "Create")
$Class.Qualifiers.Add("SupportsDelete", $true)
$Class.Qualifiers.Add("DeleteBy", "DeleteInstance")
$Class.Qualifiers.Add("Locale", 1033, $false, $true, $false, $true)
$Class.Qualifiers.Add("UUID", "{8503C4DC-5FBB-11D2-AAC1-006008C78BC7}", $false, $true, $false, $true)

$Class.Methods.Add($Name, $InParametersManagementBaseObjectInstance, $OutParametersManagementBaseObjectInstance)
$Class.Methods["$Name"].Qualifiers.Add("Constructor", $true)
$Class.Methods["$Name"].Qualifiers.Add("Static", $true)
$Class.Methods["$Name"].Qualifiers.Add("Implemented", $true)
$Class.Methods["$Name"].Qualifiers.Add("Privileges", [String[]]@("SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege", "SeRestorePrivilege"), $false, $false, $true, $true)
$Class.Methods["$Name"].Qualifiers.Add("ValueMap", [String[]]@("0", "2", "3", "8", "9", "21", ".."), $false, $false, $true, $true)
$Class.Methods["$Name"].Qualifiers.Add("MappingStrings", [String[]]"Win32API|Process and Thread Functions|CreateProcess", $false, $false, $true, $true)

$Class.Properties.Add("ProcessId", [System.Management.CimType]::UInt32, $false)
$Class.Properties["ProcessId"].Qualifiers.Add("read", $true, $false, $false, $true, $true)
$Class.Properties["ProcessId"].Qualifiers.Add("MappingStrings", [String[]]"Win32API|Process and Thread Structures|PROCESS_INFORMATION|dwProcessId ", $false, $false, $true, $true)

$Class.Properties.Add("CommandLine", [System.Management.CimType]::String, $false)
$Class.Properties["ProcessId"].Qualifiers.Add("read", $true)

$Class.Put()

(((Get-CimClass Win32_ProcessLogon).CimClassMethods | ? Name -Like CreateLogon).Parameters | ? Name -Like ProcessStartupInformation).CimType

<#
################################################################################
################################################################################
$QualifierData = $SystemManagement.GetType(‘System.Management.QualifierData’)
$QualifierData_ctor = $QualifierData.GetType().GetConstructors([Reflection.BindingFlags] "NonPublic, Instance")

################################################################################
################################################################################
Function local:Get-ManagementBaseObject {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [Object]$Class
    )
    $TempPtr = [System.IntPtr]$Class
    $TempPtr
    $DotNetPath = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
    $SystemManagement = [System.Reflection.Assembly]::LoadFile($DotNetPath+"System.Management.dll")

    $IWbemClassObjectFreeThreaded = $SystemManagement.GetType(‘System.Management.IWbemClassObjectFreeThreaded’)
    $IWbemClassObjectFreeThreaded_ctor = $IWbemClassObjectFreeThreaded.GetConstructors()[0]
    $IWbemClassObjectFreeThreadedInstance = $IWbemClassObjectFreeThreaded_ctor.Invoke($TempPtr)
    #This is the in and out param in MethodData

    $ManagementBaseObject = $SystemManagement.GetType(‘System.Management.ManagementBaseObject’)
    $ManagementBaseObject_ctor = $ManagementBaseObject.GetConstructors([Reflection.BindingFlags] "NonPublic, Instance")[1]
    $ManagementBaseObjectInstance = $ManagementBaseObject_ctor.Invoke($IWbemClassObjectFreeThreadedInstance)
    #This is the in and out param in MethodDataCollection
    Return $ManagementBaseObjectInstance
}
#>