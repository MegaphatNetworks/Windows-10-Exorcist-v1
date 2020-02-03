$Intro = @(
"# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #"
"# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #"
"# #                                                                                                                         # #" 
"# #                                                                                                                         # #" 
"# #                                      Windows 10 Crap Master Removal Script                                              # #" 
"# #                                               by Gabriel Polmar                                                         # #" 
"# #                                               Megaphat Networks                                                         # #" 
"# #                                                                                                                         # #" 
"# #                                                                                                                         # #"
"# # IMPORTANT NOTICE:  This script will make SEVERE changes to your system(s).  Use it WISELY!                              # #" 
"# # This script will remove as much of the bloatware crap that Micro$oft has decided to put on your computer(s).                # #" 
"# # Much of this crap is sponsored which means that they are only after revenues, at YOUR expense!!!                        # #" 
"# # While I am all for making money, it's obscene how much garbage that M$ has decided to put on your computer(s).          # #" 
"# # The idea here is that you paid for Windows, you did not pay for your computer to be their private ad delivery service.  # #" 
"# # This script is designed to operated on a multi-user system.  While one user may run the script as admin, other users    # #" 
"# # will find that there are still crapware features and tracking telemetry activities happening on their account(s).       # #" 
"# # This script will load once for an administrator, removing all primary crapware.  Each subsequent user who logs on       # #" 
"# # the script will then clean their profile as well.  It is up to the system administrator to determine how to implement   # #" 
"# # this script and when to discontinue using it.                                                                           # #" 
"# #                                                                                                                         # #" 
"# # ALSO IMPORTANT: The changes this script will make are *severe* meaning that your computer(s) will have radical changes  # #"
"# # made to it/them.  Not only is the crapware removed, but many telemetry, `phone-home` features and data capture as         # #"
"# # well as user experience features will be permanently disabled.  The purpose of all of this is to make the computer(s)   # #"
"# # operate more smoothly and lean for business purposes.  Home users  seeking a scaled-down Windows experience may also    # #"
"# # find a cleaner experience more refreshing.                                                                              # #"
"# #                                                                                                                         # #"
"# # Please note that it took about 200 hours of research, coding and testing to get this script working properly.           # #" 
"# # If you find it useful, please give us credit if you clone the script.  If you really want to show your thanks,          # #" 
"# # help pay for the time we spend doing this by sending us enough money to buy ourselves some coffee to keep us coding!    # #" 
"# #                                                                                                                         # #"
"# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #" 
"# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #" 
)

# # # # # # # # # # # # # # # # # 
# # CORE FUNCTION DEFINITIONS # # 
# # # # # # # # # # # # # # # # # 

Function doIntro($something) {
	foreach ($ThisLine in $Intro) {
		Write-Host "$ThisLine" -ForegroundColor yellow -BackgroundColor darkblue
	}
}

Function Wait ($secs) {
	if (!($secs)) {$secs = 1}
	Start-Sleep $secs
}

Function SetConsoleSize {
	$ThisHost = Get-Host
	$CurWin = $ThisHost.UI.RawUI
	$CurSize = $CurWin.BufferSize 
	$CurSize.Width = 130
	$CurSize.Height = 40
	$CurWin.BufferSize = $CurSize 
	$CurSize = $CurWin.WindowSize 
	$CurSize.Width = 130  
	$CurSize.Height = 40
	$CurWin.WindowSize = $CurSize
}

Function Say($something) {
	#Say something, anything!
	Write-Host $something -ForegroundColor darkblue -BackgroundColor white
}

Function isOSTypeHome {
	$ret = (Get-WmiObject -class Win32_OperatingSystem).Caption | select-string "Home"
	Return $ret
}

Function getWinVer {
	$ret = (Get-WMIObject win32_operatingsystem).version
	Return $ret
}

Function isAppInstalled ($AppName) {
	If ((Get-AppxPackage | where {$_.Name -like "*$AppName*"}).length -gt 0) {
		Return True
	} Else {
		Return False
	}
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

Function hasBeenExAdmin {
	$Path = "$Env:SystemDrive\Temp\CMRS\Global.txt"
	$ret = Test-Path $Path
	Return $ret
}

Function hasBeenExUser {
	$Path = "$Env:Temp\CMRS\Profile.txt"
	$ret = Test-Path $Path
	Return $ret
}

Function regSet ($KeyPath, $KeyItem, $KeyValue) {
	$Key = $KeyPath.Split("\")
	ForEach ($level in $Key) {
		If (!($ThisKey)) {
			$ThisKey = "$level"
		} Else {
			$ThisKey = "$ThisKey\$level"
		}
		If (!(Test-Path $ThisKey)) {New-Item $ThisKey -Force | out-null}
	}
	Set-ItemProperty $KeyPath $KeyItem -Value $KeyValue
}

Function regGet($Key, $Item) {
	If (!(Test-Path $Key)) {
		Return
	} Else {
		If (!($Item)) {$Item = "(Default)"}
		$ret = (Get-ItemProperty -Path $Key -Name $Item).$Item
		Return $ret
	}
}

Function CreateLogAdmin {
	If (!(Test-Path $CMRSA)) {
		New-Item "$CMRSA" -Force | Out-Null
	}
}

Function CreateLogUser {
	If (!(Test-Path $CMRSU)) {
		New-Item "$CMRSU" -Force | Out-Null
	}
}

# # # # # # # # # # # # # # # # # # 
# # SCRIPT-SPECIFIC DEFINITIONS # # 
# # # # # # # # # # # # # # # # # # 

Function Profile_DisableTracking {
	If (!(regGet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_DisableTracking")) {
		Say "      ********************** Entering _Profile_DisableTracking_ Routine ******************************"
		
		regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Start_TrackProgs" 0 #Disable Let Windows track app launches
		regSet "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" 1 #To turn off Send Microsoft info about how I write to help us improve typing and writing in the future	
		regSet "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" "HasAccepted" 0 #"Turn off Voice Dictation of Microsoft Speech services" 
		regSet "HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds" "" 0 #Disable System from asking for feedback
		regSet "HKCU:\Software\Microsoft\Siuf\Rules\NumberOfSIUFInPeriod" "" 0 #Disable System from asking acquiring feedback
		regSet "HKCU:\SOFTWARE\Microsoft\Messaging" "CloudServiceSyncEnabled" 0 #Disable Messaging Cloud Sync
		regSet "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightFeatures" 1 #Disable Windows Spotlight
		
		Say "      ********************** Finished _Profile_DisableTracking_ Routine ******************************"
		regSet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_DisableTracking" 1
		$Need2Reboot = 1
	} Else {
		Say "      This Profile has already executed Profile_DisableTracking"
	}
}

Function Profile_DisableCDM {
	If (!(regGet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_DisableCDM")) {
		Say "      ********************** Entering _Profile_DisableCDM_ Routine ******************************"
		Say "        Disabling Content delivery garbage..."
		
		regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" "BingSearchEnabled" 0 
		regSet "HKCU:\Software\Microsoft\Siuf\Rules" "PeriodInNanoSeconds" 0 
		regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "ContentDeliveryAllowed" 0 
		regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "OemPreInstalledAppsEnabled" 0 
		regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEnabled" 0 
		regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "PreInstalledAppsEverEnabled" 0 
		regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SilentInstalledAppsEnabled" 0 
		regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SystemPaneSuggestionsEnabled" 0          
		regSet "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoTileApplicationNotification" 1 
		#Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
		regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic" "FirstRunSucceeded" 0 
		#Checking if the Mixed Reality Portal was uninstalled properly
		if ((Get-AppxPackage -Name "Microsoft.MixedReality.Portal").length) {
			Get-AppxPackage -Name "Microsoft.MixedReality.Portal" | Remove-AppxPackage
			Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "Microsoft.MixedReality.Portal" | Remove-AppxProvisionedPackage -Online
		}
		#Disables People icon on Taskbar
		regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" "PeopleBand" 0
		
		Say "      ********************** Finished _Profile_DisableCDM_ Routine ******************************"
		regSet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_DisableCDM" 1
		$Need2Reboot = 1
	} Else {
		Say "      This Profile has already executed Profile_DisableCDM"
	}
}

Function Profile_DisableWindowsCortana {
	If (!(regGet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_DisableWindowsCortana")) {
		Say "      ********************** Entering _Profile_DisableWindowsCortana_ Routine ******************************"
		Say "        Disabling Cortana for your profile..."
		
		regSet "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0 
		regSet "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1 
		regSet "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1 
		regSet "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0    
		
		Say "      ********************** Finished _Profile_DisableWindowsCortana_ Routine ******************************"
		regSet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_DisableWindowsCortana" 1
		$Need2Reboot = 1
	} Else {
		Say "      This Profile has already executed Profile_DisableWindowsCortana"
	}
}

Function Profile_UnPinStartMenuItems {
	If (!(regGet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_UnPinStartMenuItems")) {
		Say "      ********************** Entering _Profile_UnPinStartMenuItems_ Routine ******************************"
		Say "        Unpinning all tiles from the start menu"
		(New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() |
		    % { $_.Verbs() } | ? {$_.Name -match 'Un.*pin from Start'} | % {$_.DoIt()}
		Say "      ********************** Finished _Profile_UnPinStartMenuItems_ Routine ******************************"
		regSet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_UnPinStartMenuItems" 1
	} Else {
		Say "      This Profile has already executed Profile_UnPinStartMenuItems"
	}
}

Function Global_RemoveMSCrap {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_RemoveMSCrap")) {
		Say "      ********************** Entering _Global_RemoveMSCrap_ Routine ******************************"
		Say "        Removing other misc crap from your system.  Please be patient."
		Say "        While you wait, you can Venmo me some coffee cash... just sayin'."
		
		$AppWL = '.NET|CanonicalGroupLimited.UbuntuonWindows|Framework|Microsoft.DesktopAppInstaller|Microsoft.HEIFImageExtension|`
			Microsoft.MSPaint|Microsoft.StorePurchaseApp|Microsoft.VP9VideoExtensions|Microsoft.WindowsAlarms|`
			Microsoft.WebMediaExtensions|Microsoft.WebpImageExtension|Microsoft.WindowsCalculator|Microsoft.WindowsStore|MIDIBerry|Slack|WindSynthBerry'
		
		$AppStatic = '*Nvidia*|1527c705-839a-4832-9118-54d4Bd6a0c89|c5e2524a-ea46-4f67-841f-6a9465d9d515|E2A4F912-2574-4A75-9BB0-0D023378592B|F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE|`
			InputApp|Microsoft.AAD.BrokerPlugin|Microsoft.AccountsControl|Microsoft.BioEnrollment|Microsoft.CredDialogHost|Microsoft.ECApp|Microsoft.LockApp|Microsoft.MicrosoftEdge|`
			Microsoft.MicrosoftEdgeDevToolsClient|Microsoft.PPIProjection|Microsoft.Services.Store.Engagement|Microsoft.UI.Xaml.2.0|Microsoft.VCLibs.140.00|Microsoft.Win32WebViewHost|`
			Microsoft.Windows.Apprep.ChxApp|Microsoft.Windows.AssignedAccessLockApp|Microsoft.Windows.CapturePicker|Microsoft.Windows.CloudExperienceHost|Microsoft.Windows.ContentDeliveryManager|`
			Microsoft.Windows.Cortana|Microsoft.Windows.NarratorQuickStart|Microsoft.Windows.ParentalControls|Microsoft.Windows.PeopleExperienceHost|Microsoft.Windows.PinningConfirmationDialog|`
			Microsoft.Windows.SecHealthUI|Microsoft.Windows.SecureAssessmentBrowser|Microsoft.Windows.ShellExperienceHost|Microsoft.Windows.XGpuEjectDialog|Microsoft.XboxGameCallableUI|`
			windows.immersivecontrolpanel|Windows.PrintDialog'

		Say "         Attemping to remove additional crap and bloatware from All User Profiles."
		Get-AppxPackage -AllUsers | Where-Object {$_.Name -NotMatch $AppWL -and $_.Name -NotMatch $AppStatic} | Remove-AppxPackage
		Say "         Attemping to remove additional crap and bloatware from THIS User Profile."
		Get-AppxPackage | Where-Object {$_.Name -NotMatch $AppWL -and $_.Name -NotMatch $AppStatic} | Remove-AppxPackage
		Say "         Attemping to remove additional crap and bloatware from stored online repositories and manifests."
		Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -NotMatch $AppWL -and $_.PackageName -NotMatch $AppStatic} | Remove-AppxProvisionedPackage -Online
		Say "      ********************** Finished _Global_RemoveMSCrap_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_RemoveMSCrap" 1
		$Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_RemoveMSCrap"
	}
}

Function Global_RemoveOtherCrap {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_RemoveOtherCrap")) {
		Say "      ********************** Entering _Global_RemoveOtherCrap_ Routine ******************************"
		Say "         Defining AppBL array string"
		$AppBL = @(
			"Microsoft.BingNews"
			"Microsoft.BingWeather"
			"Microsoft.GetHelp"
			"Microsoft.Getstarted"
			"Microsoft.Messaging"
			"Microsoft.Microsoft3DViewer"
			"Microsoft.MicrosoftOfficeHub"
			"Microsoft.MicrosoftSolitaireCollection"
			"Microsoft.MixedReality.Portal"
			"Microsoft.NetworkSpeedTest"
			"Microsoft.News"
			"Microsoft.Office.Lens"
			"Microsoft.Office.OneNote"
			"Microsoft.Office.Sway"
			"Microsoft.Office.Todo.List"
			"Microsoft.OneConnect"
			"Microsoft.Paint3D"
			"Microsoft.People"
			"Microsoft.Print3D"
			"Microsoft.RemoteDesktop"
			"Microsoft.SkypeApp"
			"Microsoft.MicrosoftStickyNotes"
			"Microsoft.StorePurchaseApp"
			"Microsoft.ScreenSketch"
			"Microsoft.Wallet"
			"Microsoft.Whiteboard"
			"Microsoft.WindowsCamera"
			"Microsoft.windowscommunicationsapps"
			"Microsoft.WindowsFeedbackHub"
			"Microsoft.WindowsMaps"
			"Microsoft.Windows.Photos"
			"Microsoft.WindowsSoundRecorder"
			"Microsoft.Xbox*"
			"Microsoft.Xbox.TCUI"
			"Microsoft.XboxApp"
			"Microsoft.XboxGameCallableUI"
			"Microsoft.XboxGameOverlay"
			"Microsoft.XboxGamingOverlay"
			"Microsoft.XboxIdentityProvider"
			"Microsoft.XboxSpeechToTextOverlay"
			"Microsoft.YourPhone"
			"Microsoft.ZuneMusic"
			"Microsoft.ZuneVideo"
			"Windows.CBSPreview"
			"*EclipseManager*"
			"*ActiproSoftwareLLC*"
			"*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
			"*Duolingo-LearnLanguagesforFree*"
			"*PandoraMediaInc*"
			"*CandyCrush*"
			"*Wunderlist*"
			"*Flipboard*"
			"*Twitter*"
			"*Facebook*"
			"*Spotify*"
			"*Minecraft*"
			"*Royal Revolt*"
			"*Sway*"
			"*Speed Test*"
			"*Dolby*"
			"*Netflix*"
			"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
			"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
			"*Microsoft.BingWeather*"
			"*Microsoft.WindowsStore*"
		)
		foreach ($BadApp in $AppBL) {
			Get-AppxPackage -Name $BadApp| Remove-AppxPackage
			Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $BadApp | Remove-AppxProvisionedPackage -Online
		}
		Say "      ********************** Finished _Global_RemoveOtherCrap_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_RemoveOtherCrap" 1
		$Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_RemoveOtherCrap"
	}
}

Function Global_CleanRegCrapware {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_CleanRegCrapware")) {
		Say "      ********************** Entering _Global_CleanRegCrapware_ Routine ******************************"
		Say "      Cleaning the registry from any CrapWare leftovers that the uninstallation process may have missed."
		$RegKeys = @(           
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
			"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
			"HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
			"HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
			"HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
			"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
			"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
		)
		ForEach ($Key in $RegKeys) {
			Remove-Item $Key -Recurse
		}
		Say "      ********************** Finished _Global_CleanRegCrapware_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_CleanRegCrapware" 1
		$Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_CleanRegCrapware"
	}
}
            
Function Global_DisableTelemetry {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_DisableTelemetry")) {
		Say "      ********************** Entering _Global_DisableTelemetry_ Routine ******************************"
		Say "        Disabling Microsoft telemetry..."

		#Disable WiFi tracking and reporting & turn off WiFi Sense
		
		regSet "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" "Value" 0 
		regSet "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" "Value" 0 
		regSet "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" 0 

		#Turns off Data Collection via the AllowTelemtry key by changing it to 0
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0 
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0 
		regSet "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0 

		#Disabling Location Tracking
		regSet "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0 
		regSet "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status" 0 
		

		#Disables scheduled tasks that are considered unnecessary 
		Get-ScheduledTask  XblGameSaveTaskLogon | Disable-ScheduledTask #Automatically connects to XBox Live  Network
		Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask #Automatically sends statistical data to XBox Live Network
		Get-ScheduledTask  Consolidator | Disable-ScheduledTask #Windows Customer Experience Improvement Program (WCEIP)
		Get-ScheduledTask  UsbCeip | Disable-ScheduledTask #Collects USB information about your machine 
		Get-ScheduledTask  DmClient | Disable-ScheduledTask #Collects IoT related data from the system
		Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask #Downloads IoT related data from the system

		#Disabling the Diagnostics Tracking Service
		Stop-Service "DiagTrack"
		Set-Service "DiagTrack" -StartupType Disabled

		If (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore") {
			Stop-Process Explorer.exe -Force
			Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore"
			Start-Process Explorer.exe -Wait
		}
		Say "      ********************** Finished _Global_DisableTelemetry_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_DisableTelemetry" 1
		$Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_DisableTelemetry"
	}
}

Function Global_DisableWindowsCortana {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_DisableWindowsCortana")) {
		Say "      ********************** Entering _DisableWindowsCortana_ Routine ******************************"
		Say "        Disabling Cortana on this system..."
		#Disabling Bing and Cortana.  Bing and Cortana will no longer be used the default for Windows Search.
		
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch" 1 
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_DisableWindowsCortana" 1
		
		Say "      ********************** Finished _DisableWindowsCortana_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_DisableWindowsCortana" 1
		$Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_DisableWindowsCortana"
	}
}

Function Global_DisableEdgePDF {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_DisableEdgePDF")) {
		Say "      ********************** Entering _Global_DisableEdgePDF_ Routine ******************************"
		Say "         Disabling Edge as the default PDF viewer on this system..."
		Say "         Why oh why would M$ think Edge is better?"
		If (!(Get-ItemProperty "HKCR:\.pdf"  NoOpenWith)) {New-ItemProperty "HKCR:\.pdf"  NoOpenWith }        
		If (!(Get-ItemProperty "HKCR:\.pdf"  NoStaticDefaultVerb)) {New-ItemProperty "HKCR:\.pdf"  NoStaticDefaultVerb }        
		If (!(Get-ItemProperty "HKCR:\.pdf\OpenWithProgids"  NoOpenWith)) {New-ItemProperty "HKCR:\.pdf\OpenWithProgids"  NoOpenWith }        
		If (!(Get-ItemProperty "HKCR:\.pdf\OpenWithProgids"  NoStaticDefaultVerb)) {New-ItemProperty "HKCR:\.pdf\OpenWithProgids"  NoStaticDefaultVerb }        
		If (!(Get-ItemProperty "HKCR:\.pdf\OpenWithList"  NoOpenWith)) {New-ItemProperty "HKCR:\.pdf\OpenWithList"  NoOpenWith}        
		If (!(Get-ItemProperty "HKCR:\.pdf\OpenWithList"  NoStaticDefaultVerb)) {New-ItemProperty "HKCR:\.pdf\OpenWithList"  NoStaticDefaultVerb }
		If (Test-Path "HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_") {Set-Item "HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_" "AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_"}
		Say "      ********************** Finished _Global_DisableEdgePDF_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_DisableEdgePDF" 1
		$Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_DisableEdgePDF"
	}
}

Function Global_FixSvcDMW {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_FixSvcDMW")) {
		Say "      ********************** Entering _Global_FixSvcDMW_ Routine ******************************"
		Say "        Fixing the DMW Service on your system (which may affect SysPrep)..."
		Say "         Enabling DMW App Push Service in order to ensure SysPrep works properly."
		If (Get-Service -Name dmwappushservice | Where-Object {$_.StartType -eq "Disabled"}) {
			Say "         DMW App Push Service is disabled, enabling and starting it."
			Set-Service -Name dmwappushservice -StartupType Manual
			Wait 3
		}
		If (Get-Service -Name dmwappushservice | Where-Object {$_.Status -eq "Stopped"}) {
			Say "         DMW App Push Service is stopping, starting it."
			Start-Service -Name dmwappushservice
		} 
		Say "      ********************** Finished _Global_FixSvcDMW_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_FixSvcDMW" 1
	} Else {
		Say "      Admin Elevation has already executed Global_FixSvcDMW"
	}
}

Function Global_FixCalculator {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_FixCalculator")) {
		Say "      ********************** Entering _Global_FixCalculator_ Routine ******************************"
		Say "        Fixing up the core apps on your system..."
		If (!(Get-AppxPackage -AllUsers | Select Microsoft.WindowsCalculator, Microsoft.WindowsStore)) {
			Get-AppxPackage -allusers Microsoft.WindowsCalculator | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
		} 
		Say "      ********************** Finished _Global_FixCalculator_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_FixCalculator" 1
	} Else {
		Say "      Admin Elevation has already executed Global_FixCalculator"
	}
}

Function Global_UninstallOneDrive {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_UninstallOneDrive")) {
		Say "      ********************** Entering _Global_UninstallOneDrive_ Routine ******************************"
		Say "         Verifying if the OneDrive folder is empty.  If not, moving data to a backup folder."
		If (Test-Path "$env:USERPROFILE\OneDrive\*") {
			Say "         Contents found in your OneDrive folder, relocating to Desktop."
			If (!(Test-Path "$env:USERPROFILE\Desktop\OneDrive_Backup")) {
				New-item -Path "$env:USERPROFILE\Desktop" -Name "OneDrive_Backup"-ItemType Directory -Force #| Out-Null
				Say "         Backup folder created."
				Wait
			}
			Move-Item -Path "$env:USERPROFILE\OneDrive\*" -Destination "$env:USERPROFILE\Desktop\OneDrive_Backup" -Force
		} 
		regSet "HKLM:Software\Policies\Microsoft\Windows\OneDrive" "OneDrive" "DisableFileSyncNGSC"
		Say "         Uninstalling OneDrive..."
		Stop-Process -Name "OneDrive*"
		Wait 3

		If (!(Test-Path "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe")) {
			Stop-Process -Name "OneDrive*"
			Wait 3
			If (Test-Path "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe") {Start-Process "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe" "/uninstall" -NoNewWindow -Wait} 
			ElseIf (Test-Path "$env:SYSTEMROOT\System32\OneDriveSetup.exe") {Start-Process "$env:SYSTEMROOT\System32\OneDriveSetup.exe" "/uninstall" -NoNewWindow -Wait} 
			Wait 3
			Say "         Stopping explorer to perform some cleanup tasks."
			taskkill.exe /F /IM explorer.exe
			Wait 3
			If (Test-Path "$env:USERPROFILE\OneDrive") {Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse}
			If (Test-Path "$env:LOCALAPPDATA\Microsoft\OneDrive") {Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse}
			If (Test-Path "$env:PROGRAMDATA\Microsoft OneDrive") {Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse}
			If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse}
			
			regSet "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0 
			regSet "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
			Say "         Creating Group Policy 'Prevent the usage of OneDrive for File Storage'."
			regSet "HKLM:Software\Policies\Microsoft\Windows\OneDrive" "" ""
			

			Start-Process explorer.exe -NoNewWindow
			Wait 3
			Remove-item Env:OneDrive

			
			regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1 #Disable OneDrive sync
			regSet "HKLM:\SOFTWARE\Microsoft\OneDrive" "PreventNetworkTrafficPreUserSignIn" 1 #Disable OneDrive sign in
			

			Say "         OneDrive has been removed."
		}
		Say "      ********************** Finished _Global_UninstallOneDrive_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_UninstallOneDrive" 1
		$Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_UninstallOneDrive"
	}
}

Function Global_Remove3DObjects {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_Remove3DObjects")) {
		Say "      ********************** Entering _Global_Remove3DObjects_ Routine ******************************"
		Say "        Removing 3D Objects from explorer 'My Computer' submenu"
		$Objects32 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
		$Objects64 = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
		If (Test-Path $Objects32) {Remove-Item $Objects32 -Recurse}
		If (Test-Path $Objects64) {Remove-Item $Objects64 -Recurse}
		Say "      ********************** Finished _Global_Remove3DObjects_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_Remove3DObjects" 1
	} Else {
		Say "      Admin Elevation has already executed Global_Remove3DObjects"
	}
}

Function Global_SetSystemPolicies {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_SetSystemPolicies")) {
		Say "      ********************** Entering _Global_SetSystemPolicies_ Routine ******************************"
		
		#Disabling Global Machine Tracking 
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice\AllowFindMyDevice" "" 0 #Disabling: Windows Find My Device
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" "DoNotTrack" 1 #Enable Microsoft Edge Configure Do Not Track

		#Disabling Global Windows Experience Features
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" "AllowBuildPreview" 0 #Disabling: Insider Preview builds
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoCloudApplicationNotification" 1 #Live Tiles
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" "NoActiveProbe" 1 #Disable Network Connection Status Indicator
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" "AutoDownloadAndUpdateMapData" 0 #Disable Offline maps auto update
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" "AllowUntriggeredNetworkTrafficOnSettingsPage" 0 #Disable Offline maps sync
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoCloudApplicationNotification" 1 #Turn off notifications network usage
		regSet "HKLM:\Software\Policies\Microsoft\Speech" "AllowSpeechModelUpdate" 0 #Turn off speech mode updates
		
		#Enhancing Global System Privacy Policies
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows Mail" "ManualLaunchAllowed" 0 #Mail synchronization
		regSet "HKLM:\System\CurrentControlSet\Services\wlidsvc" "" 4 #Disable Microsoft Account Sign-In Assistant
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0 #Disable Let apps use advertising ID to make ads more interesting (Feedback Experience Program)
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1 #Disable Let apps use advertising ID sync
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0 #Disable Let apps use my advertising ID for experiences across apps
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1 #Disable AD ID
		regSet "HKLM:\Software\Policies\Microsoft\Windows\System" "EnableCdp" 0 #Turn off Let apps on my other devices open apps and continue experiences on this device
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessLocation" 2 #Disable App Location Access
		regSet "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1 #Disable System Location Access
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCamera" 2 #Let apps use my camera
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMicrophone" 2 #Let apps use my microphone
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessNotifications" 2 #Turn off Let apps access my notifications
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy" "LetAppsAccessAccountInfo" 2 #Let apps access my name, picture, and other account info
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy" "LetAppsAccessContacts" 2 #Disable Apps from accessing Contacts
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy" "LetAppsAccessCalendar" 2 #Disable Apps from accessing Calendar
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCallHistory" 2 #Disable Apps from accessing Call history
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessEmail" 2 #Disable Apps from accessing Email
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMessaging" 2 #Disable Apps from accessing Messaging
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessPhone" 2 #Disable Apps from accessing Phone
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessRadios" 2 #Disable Apps from accessing Radios
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsSyncWithDevices" 2 #Disable Apps from accessing Device Sync
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessTrustedDevices" 2 #Disable Apps from accessing Trusted Devices
		regSet "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" 1 #Disable Apps from asking for feedback
		regSet "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry" "" 0 #Disable System from sending MS telemetry
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" 1 #Disable Tailored Experience Diagnostic Data
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2 #Disable Apps from running in the background
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMotion" 2 #Disable Apps from Accessing Motion
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessTasks" 2 #Disable Apps from accessing Tasks
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsGetDiagnosticInfo" 2 #Disable Apps from getting diagnostic data
		regSet "HKLM:\Software\Policies\Microsoft\Windows\System" "EnableActivityFeed" 2 #Disable Activity Feed
		regSet "HKLM:\Software\Policies\Microsoft\Windows\System" "PublishUserActivities" 2 #Disable Publish User Activity
		regSet "HKLM:\Software\Policies\Microsoft\Windows\System" "UploadUserActivities" 2 #Disable Upload User Activity
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsActivateWithVoice" 2 #Disable App Voice Activation
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsActivateWithVoiceAboveLock" 2 #Disable Unlock App Voice Activation
		regSet "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" "DisableSettingSync" 2 #Disable Settings > Accounts > Sync your settings
		regSet "HKLM:\Software\Policies\Microsoft\Windows\SettingSync" "DisableSettingSyncUserOverride" 1 #Disable Settings > Accounts > Sync Override
		regSet "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent" "" 2 #Disable Windows Defender sending file samples to Microsoft
		regSet "HKLM:\Software\Policies\Microsoft\MRT\DontReportInfectionInformation" "" 1 #Disable Malicious Software Reporting Tool (MSRT) diagnostic data
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" "DisableEnhancedNotifications" 1 #Disable Malicious Software Reporting Tool (MSRT) Enhanced Notifications
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "NoLockScreen" 1 #Disable Windows Spotlight Lock Screen
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "LockScreenImage" "C:\Windows\Web\Screen\img105.jpg" #Disable Windows Spotlight Lock Screen Image
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" "LockScreenOverlaysDisabled" 1 #Disable Windows Spotlight Lock Screen Image
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableSoftLanding" 1 #Disable Soft Landing
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1 #Disable System Consumer Features
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "DisableStoreApps" 1 #Disable Microsoft Store Apps
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2 #Disable Microsoft Store Auto Downloads
		
		Say "      ********************** Finished _Global_SetSystemPolicies_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_SetSystemPolicies" 1
		$Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_SetSystemPolicies"
	}
}

Function Global_SetUpdatePolicies {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_SetUpdatePolicies")) {
		Say "      ********************** Entering _Global_SetUpdatePolicies_ Routine ******************************"
		regSet "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" "AutoDownload" 5 #Disable Windows Updates (not recommended by MS)
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 100 #Windows Update Delivery Optimization (LAN Update install from other PCs)
		regSet "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "DoNotConnectToWindowsUpdateInternetLocations" 1 #Disable Windows Updates from Internet
		regSet "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "DisableWindowsUpdateAccess" 1 #Disable Windows Updates Access
		regSet "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "WUServer" " " #Disable Windows Update Primary Server
		regSet "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "WUStatusServer" " " #Disable Windows Update Server Status
		regSet "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate" "UpdateServiceUrlAlternate" " " #Disable Windows Update Alt Server
		
		Say "      ********************** Finished _Global_SetUpdatePolicies_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_SetUpdatePolicies" 1
		$Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_SetUpdatePolicies"
	}
}

	$ErrorActionPreference = 'SilentlyContinue'
	If (!($args[0] -eq "elevate")) {
		SetConsoleSize
		doIntro $Intro
	}
	Wait 3

	$doGlobal_Config = 1				#Change this to 1 in order to execute ANY Admin Privileged-level routines
	$doGlobal_RemoveMSCrap = 0			#Change to 1 in order to remove the MS added crapware
	$doGlobal_RemoveOtherCrap = 0		#Change to 1 in order to get rid of sponsored crapware
	$doGlobal_CleanRegCrapware = 0		#Change to 1 in order to clean the registry from crapware.  Should be performed if doGlobal_RemoveOtherCrap = 1
	$doGlobal_DisableTelemetry = 0		#Change to 1 in order to Disable MS telemetry and tracking.
	$doGlobal_DisableWindowsCortana = 0	#Change to 1 in order to turn off Cortana as the Windows Search Provider
	$doGlobal_DisableEdgePDF = 0		#Change to 1 in order to disable MS Edge as the default PDF reader
	$doGlobal_FixSvcDMW = 0				#Change to 1 in order to fix the DMW service which may be affected by the operations within
	$doGlobal_FixCalculator = 0			#Change to 1 in order to fix the calculator app
	$doGlobal_UninstallOneDrive = 0		#Change to 1 in order to uninstall MS OneDrive
	$doGlobal_Remove3DObjects = 0		#Change to 1 in order to Remove the 3D Objects folder from Explorer
	$doGlobal_SetSystemPolicies = 0		#Change to 1 in order to set system policies to prevent crapware from returning
	$doGlobal_SetUpdatePolicies = 0		#Change to 1 in order to set Windows Updates policies to prevent Windows Updates from being automatic
	
	$doProfile_Config = 1 				#Change this to 1 in order to execute ANY Profile-level routines
	$doProfile_DisableCDM = 0			#Change to 1 in order to disable MScontent delivery
	$doProfile_DisableWindowsCortana = 0#Change to 1 in order to turn off Cortana as the Windows Search Provvider to the logged-on profile
	$doProfile_UnPinStartMenuItems = 0	#Change to 1 in order to Un-pin start menu items
	$doProfile_DisableTracking = 0		#Change to 1 in order to disable MS tracking

	$Need2Reboot = 0
	$CMRSP = "$Env:SystemDrive\Temp\CMRS\"
	$CMRSA = "$Env:SystemDrive\Temp\CMRS\Global.txt"
	$CMRSU = "$Env:Temp\CMRS\Profile.txt"

	Start-Transcript -OutputDirectory "$CMRSP" | Out-Null

	If (!($doGlobal_Config)) {
		Say "Global flag is set to 0.  No tasks will be performed on the Global/System level."
	} Else {
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
				If (!($doGlobal_RemoveMSCrap )) {Say "      doGlobal_RemoveMSCrap set to 0, not executing Global_RemoveMSCrap"} Else {Global_RemoveMSCrap}
				If (!($doGlobal_RemoveOtherCrap )) {Say "      doGlobal_RemoveOtherCrap set to 0, not executing Global_RemoveOtherCrap"} Else {Global_RemoveOtherCrap}
				If (!($doGlobal_CleanRegCrapware )) {Say "      doGlobal_CleanRegCrapware set to 0, not executing Global_CleanRegCrapware"} Else {Global_CleanRegCrapware}
				If (!($doGlobal_DisableTelemetry )) {Say "      doGlobal_DisableTelemetry set to 0, not executing Global_DisableTelemetry"} Else {Global_DisableTelemetry}
				If (!($doGlobal_DisableWindowsCortana )) {Say "      doGlobal_DisableWindowsCortana set to 0, not executing Global_DisableWindowsCortana"} Else {Global_DisableWindowsCortana}
				If (!($doGlobal_DisableEdgePDF )) {Say "      doGlobal_DisableEdgePDF set to 0, not executing Global_DisableEdgePDF"} Else {Global_DisableEdgePDF}
				If (!($doGlobal_FixSvcDMW )) {Say "      doGlobal_FixSvcDMW set to 0, not executing Global_FixSvcDMW"} Else {Global_FixSvcDMW}
				If (!($doGlobal_FixCalculator )) {Say "      doGlobal_FixCalculator set to 0, not executing Global_FixCalculator"} Else {Global_FixCalculator}
				If (!($doGlobal_UninstallOneDrive )) {Say "      doGlobal_UninstallOneDrive set to 0, not executing Global_UninstallOneDrive"} Else {Global_UninstallOneDrive}
				If (!($doGlobal_Remove3DObjects )) {Say "      doGlobal_Remove3DObjects set to 0, not executing Global_Remove3DObjects"} Else {Global_Remove3DObjects}
				If (!($doGlobal_SetSystemPolicies)) {Say "      doGlobal_SetSystemPolicies set to 0, not executing Global_SetSystemPolicies"} Else {Global_SetSystemPolicies}
				If (!($doGlobal_SetUpdatePolicies)) {Say "      doGlobal_SetUpdatePolicies set to 0, not executing Global_SetUpdatePolicies"} Else {Global_SetUpdatePolicies}
				Say "      Privileged-level routine execution is completed."
			} 
		} Else {
			Say "  This user account is not an Admin on the system."
		}
	}	

	Say ""
	If (!($doProfile_Config)) {
		Say "Profile flag is set to 0.  No tasks will be performed on the Profile/User level."
	} Else {	
		#Check if non-admin execution has been performed
		#Execute Profile-level routines
		Say "Starting the execution of the script for the user profile $env:username..."
		If (!($doProfile_DisableCDM)) {Say "      doProfile_DisableCDM set to 0, not executing Profile_DisableCDM"} Else {Profile_DisableCDM}
		If (!($doProfile_DisableWindowsCortana)) {Say "      doProfile_DisableWindowsCortana set to 0, not executing Profile_DisableWindowsCortana"} Else {Profile_DisableWindowsCortana}
		If (!($doProfile_UnPinStartMenuItems)) {Say "      doProfile_UnPinStartMenuItems set to 0, not executing Profile_UnPinStartMenuItems"} Else {Profile_UnPinStartMenuItems}
		If (!($doProfile_DisableTracking)) {Say "      doProfile_DisableTracking set to 0, not executing Profile_DisableTracking"} Else {Profile_DisableTracking}
		Say "Completed the execution of the script for the user profile $env:username."
	}
	
    Say "Windows 10 CMRS has completed."
    Stop-Transcript | Out-Null
    
    If ($Need2Reboot) {
		Say "Your system has been modified and requires a restart.  Automatically restarting in 10 seconds..."
		Wait 1
		Restart-Computer
	}
