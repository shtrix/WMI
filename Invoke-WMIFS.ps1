<#

Example run of it
1. Create the Class
2. Get the Class String Length
3. Read in the File as bytes and Base64 Encode it
4. Split up the Base64 Encoded File and Insert it 
5. Pull the File back out from WMI and Reassemble it
6. Convert the file from Base64 back to bytes and write it to disk

New-WMIClass -ClassName WMIFS -Verbose

$length = Get-WMILength -Verbose -ClassName WMIFS
$EncodedText = ConvertTo-Base64 -FileName "cmd.exe" -Verbose
Invoke-InsertFile -EncodedText $EncodedText -FileName "cmd.exe" -ClassName WMIFS -StrLen $length -Verbose

$File = Invoke-RetrieveFile -FileName "cmd.exe" -ClassName WMIFS -Verbose
ConvertFrom-Base64 -EncodedText $File -FileName 'C:\calc.exe' -Verbose

Remove-WmiObject WMIFS
#>

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
            [string]$ClassName = 'WMIFS'
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
                } | Out-Null
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
            [string]$ClassName = 'WMIFS'
    )
    Begin {
        $Class = New-Object System.Management.ManagementClass("root\cimv2", [String]::Empty, $null); 
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
            [string]$StrLen = 8000
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
            [string]$ClassName = 'WMIFS'
    )
    Begin {
    } Process {
        $query = Get-WmiObject -Query "SELECT * FROM $ClassName WHERE FileName LIKE '$FileName'"
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

################################################################################
# Covert the file back from Base64 to bytes
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
            [switch]$WriteToDisk
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