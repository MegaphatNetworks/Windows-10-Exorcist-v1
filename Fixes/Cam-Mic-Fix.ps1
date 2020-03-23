
Function Wait ($secs) {if (!($secs)) {$secs = 1};Start-Sleep $secs}

Function Say($something) {Write-Host $something -ForegroundColor darkblue -BackgroundColor white}

Function isOSTypeHome {$ret = (Get-WmiObject -class Win32_OperatingSystem).Caption | select-string "Home";Return $ret}

Function getWinVer {$ret = (Get-WMIObject win32_operatingsystem).version;Return $ret}

Function isAppInstalled ($AppName) {
	If ((Get-AppxPackage | where {$_.Name -like "*$AppName*"}).length -gt 0) {Return True} Else {Return False}
}

Function isAdminLocal {
	$ret = (new-object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole("Administrators")
	Return $ret
}

Function isAdminDomain {
	$ret = (new-object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole("Domain Admins")
	Return $ret
}

Function isElevated {
	$ret = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')
	Return $ret
}

Function hasBeenExAdmin {$Path = "$Env:SystemDrive\Temp\CMRS\Global.txt";$ret = Test-Path $Path;Return $ret}

Function hasBeenExUser {$Path = "$Env:Temp\CMRS\Profile.txt";$ret = Test-Path $Path;Return $ret}

Function regSet ($KeyPath, $KeyItem, $KeyValue) {
	$Key = $KeyPath.Split("\")
	ForEach ($level in $Key) {
		If (!($ThisKey)) {$ThisKey = "$level"} Else {$ThisKey = "$ThisKey\$level"}
		If (!(Test-Path $ThisKey)) {New-Item $ThisKey -Force | out-null}
	}
	Set-ItemProperty $KeyPath $KeyItem -Value $KeyValue
}

Function regGet($Key, $Item) {
	If (!(Test-Path $Key)) {Return} Else {
		If (!($Item)) {$Item = "(Default)"}
		$ret = (Get-ItemProperty -Path $Key -Name $Item).$Item
		Return $ret
	}
}

# # # # # # # # # # # # # # # # # # 
# # SCRIPT-SPECIFIC DEFINITIONS # # 
# # # # # # # # # # # # # # # # # # 


Function Global_SetSystemPolicies {
		Say "      ********************** Entering _Global_SetSystemPolicies_ Routine ******************************"
		
		
		#Enhancing Global System Privacy Policies
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCamera" 0 #Let apps use my camera
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMicrophone" 0 #Let apps use my microphone
}


	$ErrorActionPreference = 'SilentlyContinue'
	$CMRSP = "$Env:SystemDrive\Temp\CMRS\"

	Start-Transcript -OutputDirectory "$CMRSP" | Out-Null

	Say "Performing version check..."
	If (isOSTypeHome) {
		Say "Windows HOME Edition detected - checking privileges..."
		If (!(isAdminLocal)) {
			Say "Attempting to elevate now priviledges..."
			Wait
			Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`" elevate" -f $PSCommandPath) -Verb RunAs
			Exit
		} else {
			Say "Script has been executed with Elevated permissions.  Continuing..."
		}
	}
	#Since a Home OS will always return False here, Home will pretty much ignore this next block.
	Say "Check if Admin execution has been performed..."
	If (isAdminLocal -Or isAdminDomain) {
		Say "  Account is a SysAdmin.  Checking for previous administrative execution..."
		If (!(isElevated)) {
			Say "      Script was not launched with Elevated permissions, attempting now."
			Wait 2
			Start-Process PowerShell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -File `"{0}`" elevate" -f $PSCommandPath) -Verb RunAs
		} Else {
			Say "      Script executed with elevated rights - continuing."
			Say "      Performing Privileged execution routines..."
			Global_SetSystemPolicies
			
			Say "      Privileged-level routine execution is completed."
		} 
	} Else {
		Say "  This user account is not an Admin on the system."
	}

	Say "Windows 10 Exorcist - Camera and Microphone has been restored and set to manual."
	Stop-Transcript | Out-Null
   
	Write "The power of Christ compels you! - Fr Damien Karras 1973"
