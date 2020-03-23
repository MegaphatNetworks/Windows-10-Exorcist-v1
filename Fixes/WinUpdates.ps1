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

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# #                                                                     # # 
# #                     SCRIPT-SPECIFIC DEFINITIONS                     # # 
# #                                                                     # # 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


Function Global_SetUpdatePolicies {
		Say "      ********************** Entering _Global_SetUpdatePolicies_ Routine ******************************"
		regSet "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" "AutoDownload" 1 #Disable Windows Updates (not recommended by MS)
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 100 #Windows Update Delivery Optimization (LAN Update install from other PCs)
		regSet "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "DoNotConnectToWindowsUpdateInternetLocations" 1 #Disable Windows Updates from Internet
		regSet "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "DisableWindowsUpdateAccess" 0 #Disable Windows Updates Access
		regSet "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "WUServer" " " #Disable Windows Update Primary Server
		regSet "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "WUStatusServer" " " #Disable Windows Update Server Status
		regSet "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "UpdateServiceUrlAlternate" " " #Disable Windows Update Alt Server
		regSet "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "UseWUServer" 0 #Disable Windows Update Auto-Update Check Service
		
		Say "      ********************** Finished _Global_SetUpdatePolicies_ Routine ******************************"
}

	$ErrorActionPreference = 'SilentlyContinue'
	If (!($args[0] -eq "elevate")) {
		$curdir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
	}
	Wait 3

	$CMRSP = "$Env:SystemDrive\Temp\CMRS\"

	Start-Transcript -OutputDirectory "$CMRSP" | Out-Null

	#At this time we need to determine if this is a Home or Business level machine.  
	#If it is a Home machine, it needs to verify Elevated permissions differently from a business machine.
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
			#We have Elevated rights, execute the rest of the Global routines.
			Global_SetUpdatePolicies
			Say "      Privileged-level routine execution is completed."
		} 
	} Else {
		Say "  This user account is not an Admin on the system."
	}
	
	Say "Windows 10 Exorcist - Windows Update has been reactivated and set to manual."
	Stop-Transcript | Out-Null
   
	Write "The power of Christ compels you! - Fr Damien Karras 1973"
