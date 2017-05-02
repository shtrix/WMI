################################################################################
# https://msdn.microsoft.com/en-us/library/aa389752(v=vs.85).aspx
################################################################################
$__PARAMETERS = New-Object System.Management.ManagementClass("ROOT", "__PARAMETERS", $null)

################################################################################
################################################################################
$InParameters = $__PARAMETERS.Clone()
$InParameters.Qualifiers.Add("In", $true)

$InParameters.Properties.Add("CommandLine", [System.Management.CimType]::String, $false)
$InParameters.Properties["CommandLine"].Qualifiers.Add("In", $true)
$InParameters.Properties["CommandLine"].Qualifiers.Add("ID", 0)
$InParameters.Properties["CommandLine"].Qualifiers.Add("MappingStrings", "Win32API|Process and Thread Functions|lpCommandLine")

$InParameters.Properties.Add("CurrentDirectory", [System.Management.CimType]::String, $false)
$InParameters.Properties["CurrentDirectory"].Qualifiers.Add("In", $true)
$InParameters.Properties["CurrentDirectory"].Qualifiers.Add("ID", 1)
$InParameters.Properties["CurrentDirectory"].Qualifiers.Add("MappingStrings", "Win32API|Process and Thread Functions|CreateProcess|lpCurrentDirectory")

$InParameters.Properties.Add("ProcessStartupInformation", [System.Management.CimType]::Object, $false)
$InParameters.Properties["ProcessStartupInformation"].Qualifiers.Add("In", $true)
$InParameters.Properties["ProcessStartupInformation"].Qualifiers.Add("ID", 2)
$InParameters.Properties["ProcessStartupInformation"].Qualifiers.Add("MappingStrings", "WMI|Win32_ProcessStartup")

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
$OutParameters.Qualifiers.Add("Out", $true)
#$OutParameters.Properties.Add("ProcessId", [System.Management.CimType]::UInt32, $false)
#$OutParameters.Properties["ProcessId"].Qualifiers.Add("Out", $true)
#$InParameters.Properties["ProcessStartupInformation"].Qualifiers.Add("ID", 0)
#$OutParameters.Properties["ProcessId"].Qualifiers.Add("MappingStrings", "Win32API|Process and Thread Functions|CreateProcess|lpProcessInformation|dwProcessId")

$OutParameters.Properties.Add("ReturnValue", [System.Management.CimType]::UInt32, $false)
#$InParameters.Properties["ProcessStartupInformation"].Qualifiers.Add("ID", 0)
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
#$Origin = "Win32_ProcessLogon"
$ClassName = "Win32_ProcessLogon"

$Class = New-Object System.Management.ManagementClass("root\cimv2", [String]::Empty, $null); 
$Class["__CLASS"] = $ClassName;

$Name = "CreateLogon"

$Class.Methods.Add($Name, $InParametersManagementBaseObjectInstance, $OutParametersManagementBaseObjectInstance)
#Add(string methodName, ManagementBaseObject inParameters, ManagementBaseObject outParameters)

$Class.Methods["$Name"].Qualifiers.Add("Constructor", $true)
$Class.Methods["$Name"].Qualifiers.Add("Implemented", $true)
$Class.Methods["$Name"].Qualifiers.Add("MappingStrings", "Win32API|Process and Thread Functions|CreateProcess")
$Class.Methods["$Name"].Qualifiers.Add("Privileges", @("SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege", "SeRestorePrivilege"))
$Class.Methods["$Name"].Qualifiers.Add("Static", $true)
$Class.Methods["$Name"].Qualifiers.Add("ValueMap", @("0", "2", "3", "8", "9", "21", ".."))

#InParameters -> IWbemClassObjectFreeThreaded -> ManagementBaseObject1
#OutParameters -> IWbemClassObjectFreeThreaded -> ManagementBaseObject2
# Create, ManagementBaseObject1, ManagementBaseObject2




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