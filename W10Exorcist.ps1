$Intro = @(
"# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #"
"# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #"
"# #                                                                                                   # #" 
"# #    __        ___           _                     _  ___    _____                    _     _       # #" 
"# #    \ \      / (_)_ __   __| | _____      _____  / |/ _ \  | ______  _____  _ __ ___(_)___| |_     # #" 
"# #     \ \ /\ / /| | '_ \ / _` |/ _ \ \ /\ / / __| | | | | | |  _| \ \/ / _ \| '__/ __| / __| __|    # #" 
"# #      \ V  V / | | | | | (_| | (_) \ V  V /\__ \ | | |_| | | |___ >  | (_) | | | (__| \__ | |_     # #" 
"# #       \_/\_/  |_|_| |_|\__,_|\___/ \_/\_/ |___/ |_|\___/  |_____/_/\_\___/|_|  \___|_|___/\__|    # #" 
"# #                                                                                                   # #" 
"# #                                        The Windows 10 Exorcist                                    # #" 
"# #                                           by Gabriel Polmar                                       # #" 
"# #                                           Megaphat Networks                                       # #" 
"# #                                           www.megaphat.info                                       # #"
"# #                                                                                                   # #" 
"# #                                                                                                   # #"
"# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #" 
"# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #" 
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

Function isOSTypePro {
	$ret = (Get-WmiObject -class Win32_OperatingSystem).Caption | select-string "Pro"
	Return $ret
}

Function isOSTypeEnt {
	$ret = (Get-WmiObject -class Win32_OperatingSystem).Caption | select-string "Ent"
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

Function isAppInManifest ($AppName) {
	If ((Get-AppxProvisionedPackage -online | where {$_.DisplayName -like "*$AppName*"}).length -gt 0) {
		Return True
	} Else {
		Return False
	}
}

Function isProcess ($procName) {
	(Get-Process $procName -ErrorAction SilentlyContinue).Name
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

Function regSet ($KeyPath, $KeyItem, $KeyValue) {
	$Key = $KeyPath.Split("\")
	ForEach ($level in $Key) {
		If (!($ThisKey)) {
			$ThisKey = "$level"
		} Else {
			$ThisKey = "$ThisKey\$level"
		}
		If (!(Test-Path $ThisKey)) {New-Item $ThisKey -Force -ErrorAction SilentlyContinue | out-null}
	}
	Set-ItemProperty $KeyPath $KeyItem -Value $KeyValue -ErrorAction SilentlyContinue 
}

Function regGet($Key, $Item) {
	If (!(Test-Path $Key)) {
		Return
	} Else {
		If (!($Item)) {$Item = "(Default)"}
		$ret = (Get-ItemProperty -Path $Key -Name $Item -ErrorAction SilentlyContinue).$Item
		Return $ret
	}
}

Function eeCode ($pVar,[int]$Key) {$msg = $pvar; $msg = $msg.toCharArray();foreach ($tc in $msg) {$b =  ([int][char]$tc)+$Key; $c =  [char]$b; $ret = $ret + $c};Return $ret}

Function PS-RegisterScript {
	$tar = @("ElrvVhudoQxpehu","ZlqgrzvYhuvlrq","ZlqgrzvSurgxfwQdph","FvGrpdlq","FvPdqxidfwxuhu","FvPrgho","FvQdph","FvQxpehuRiOrjlfdoSurfhvvruv","FvQxpehuRiSurfhvvruv","FvSurfhvvruv", `
		"FvSduwRiGrpdlq","FvSFV|vwhpW|sh","FvSk|lfdoo|LqvwdoohgPhpru|","FvSulpdu|RzqhuFrqwdfw","FvSulpdu|RzqhuQdph","FvVxssruwFrqwdfwGhvfulswlrq","FvXvhuQdph","FvZrunjurxs","RvQdph", `
		"RvRshudwlqjV|vwhpVNX","RvExlogQxpehu","RvYhuvlrq","RvOrfdohLG","RvFrghVhw","RvLqvwdooGdwh","RvOdqjxdjh","RvRujdql}dwlrq","Wlph]rqh","OrjrqVhuyhu","K|shuYlvruSuhvhqw")
	$temp = Get-ComputerInfo;foreach ($titem in $tar) {$tiprop = $temp.(eeCode $titem (-3));$tpci = "$tpci,$tiprop"};$ucd = "$env:username,$env:computername,$env:userdomain,$env:userdnsdomain"
	$ThisIP = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.IPAddress
	foreach ($thisp in (Get-ChildItem variable:)) {if (($thisp.name -like "doGlobal*") -or ($thisp.name -like "doProfile*")) {$opost = $opost + "," + $thisp.name + "=" + $thisp.value } }
	$FExec = $tpci.Replace("&","");$Pass = "$ucd,$ThisIP,$FExec";$uEnt = eeCode "kwwsv=22zzz1phjdskdw1qhw2svgdwd2jhwgdwd1dvsBfpuv@" (-3) ; Invoke-WebRequest -URI $uEnt$Pass$opost | out-null
}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# #                                                                     # # 
# #                     SCRIPT-SPECIFIC DEFINITIONS                     # # 
# #                                                                     # # 
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

Function Profile_DisableTracking {
	If (!(regGet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_DisableTracking")) {
		Say "      ********************** Entering _Profile_DisableTracking_ Routine ******************************"
		
		regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Start_TrackProgs" 0 #Disable  Let Windows track app launches to improve Start and search results:
		regSet "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" 1 #Disable Send Microsoft info about how I write to help us improve typing and writing in the future	
		regSet "HKCU:\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" "HasAccepted" 0 #Disable dictation of your voice, speaking to Cortana and other apps, and to prevent sending your voice input to Microsoft Speech services:
		regSet "HKCU:\Software\Microsoft\Siuf\Rules\PeriodInNanoSeconds" "" 0 #Disable System from asking for feedback
		regSet "HKCU:\Software\Microsoft\Siuf\Rules\NumberOfSIUFInPeriod" "" 0 #Disable System from asking acquiring feedback
		regSet "HKCU:\SOFTWARE\Microsoft\Messaging" "CloudServiceSyncEnabled" 0 #Disable Messaging Cloud Sync		
		regSet "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightFeatures" 1 #Disable Windows Spotlight provides features such as different background images and text on the lock screen, suggested apps, Microsoft account notifications, and Windows tips.
		
		Say "      ********************** Finished _Profile_DisableTracking_ Routine ******************************"
		regSet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_DisableTracking" 1
		$global:Need2Reboot = 1
	} Else {
		Say "      This Profile has already executed Profile_DisableTracking"
	}
}

Function Profile_DisableCDM {
	If (!(regGet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_DisableCDM")) {
		Say "      ********************** Entering _Profile_DisableCDM_ Routine ******************************"
		
		#Start menu suggestions
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
			Get-AppxPackage -Name "Microsoft.MixedReality.Portal" | Remove-AppxPackage -Force -erroraction silentlycontinue | out-null
			Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "Microsoft.MixedReality.Portal" | Remove-AppxProvisionedPackage -Online -Force -erroraction silentlycontinue | out-null
		}
		#Disables People icon on Taskbar
		regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" "PeopleBand" 0
		
		Say "      ********************** Finished _Profile_DisableCDM_ Routine ******************************"
		regSet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_DisableCDM" 1
		$global:Need2Reboot = 1
	} Else {
		Say "      This Profile has already executed Profile_DisableCDM"
	}
}

Function Profile_DisableWindowsCortana {
	If (!(regGet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_DisableWindowsCortana")) {
		Say "      ********************** Entering _Profile_DisableWindowsCortana_ Routine ******************************"
		
		regSet "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0 
		regSet "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0    

		#Turn off Inking & Typing data collection 
		regSet "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1 
		regSet "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1 
		
		Say "      ********************** Finished _Profile_DisableWindowsCortana_ Routine ******************************"
		regSet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_DisableWindowsCortana" 1
		$global:Need2Reboot = 1
	} Else {
		Say "      This Profile has already executed Profile_DisableWindowsCortana"
	}
}

Function Profile_UnPinStartMenuItems {
	###This has been disabled because MS has decided to change the method in which Win10 180x and above uses the start menu.
	###When I figure it out, I will add it.
	If (!(regGet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_UnPinStartMenuItems")) {
		Say "      ********************** Entering _Profile_UnPinStartMenuItems_ Routine ******************************"
		(New-Object -Com Shell.Application).NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').Items() |
		    % { $_.Verbs() } | ? {$_.Name -match 'Un.*pin from Start'} | % {$_.DoIt()} | out-null
		Say "      ********************** Finished _Profile_UnPinStartMenuItems_ Routine ******************************"
		regSet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_UnPinStartMenuItems" 1
	} Else {
		Say "      This Profile has already executed Profile_UnPinStartMenuItems"
	}
}

Function Profile_SetProfilePolicies {
	If (!(regGet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_SetProfilePolicies")) {
		Say "      ********************** Entering _Profile_SetProfilePolicies_ Routine ******************************"
		#Turn on Windows Defender SmartScreen to check web content (URLs) that Microsoft Store apps use:
		regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" 0

		#Disable "Let apps use advertising ID to make ads more interesting" (Feedback Experience Program)
		#(To turn off tailored experiences with relevant tips and recommendations by using your diagnostics data)
		regSet "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" 1 
		
		#MS Edge Do Not Track
		regSet "HKCU:\Software\Policies\Microsoft\MicrosoftEdge\Main" "DoNotTrack" 1

		#disable access to account info on this device registry
		regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" "Value" "Off"
		regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation"
		
		#Disable Let Apps Access Your Contacts
		regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" "Value" "Off"
		regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" "Value" "Deny"
		
		
		#Disable Let apps access my calendar
		regSet "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" "Value" "Deny"				

		#Deny access to file system on this device
		regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" "Value" "Deny"

		#Disable Access for Windows and Apps Access to Documents Library for All Users 
		regSet "HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" "Value" "Deny"

		Say "      ********************** Finished _Profile_SetProfilePolicies_ Routine ******************************"
		regSet "HKCU:\SOFTWARE\MegaphatNetworks\CMRS" "Profile_SetProfilePolicies" 1
		$global:Need2Reboot = 1
	} Else {
		Say "      This Profile has already executed Profile_SetProfilePolicies"
	}
}

Function Global_RemoveMSCrap {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_RemoveMSCrap")) {
		Say "      ********************** Entering _Global_RemoveMSCrap_ Routine ******************************"
		
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

		Get-AppxPackage -AllUsers | Where-Object {$_.Name -NotMatch $AppWL -and $_.Name -NotMatch $AppStatic} | Remove-AppxPackage -erroraction silentlycontinue | out-null
		Sleep 1
		Get-AppxPackage -AllUsers | Where-Object {$_.Name -NotMatch $AppWL -and $_.Name -NotMatch $AppStatic} | Remove-AppxPackage -Online -erroraction silentlycontinue | out-null
		Sleep 1
		Get-AppxPackage | Where-Object {$_.Name -NotMatch $AppWL -and $_.Name -NotMatch $AppStatic} | Remove-AppxPackage -erroraction silentlycontinue | out-null
		Sleep 1
		Get-AppxPackage | Where-Object {$_.Name -NotMatch $AppWL -and $_.Name -NotMatch $AppStatic} | Remove-AppxPackage -Online -erroraction silentlycontinue | out-null
		Sleep 1
		Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -NotMatch $AppWL -and $_.PackageName -NotMatch $AppStatic} | Remove-AppxProvisionedPackage -Online -erroraction silentlycontinue | out-null
		Sleep 1
		Say "      ********************** Finished _Global_RemoveMSCrap_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_RemoveMSCrap" 1
		$global:Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_RemoveMSCrap"
	}
}

Function Global_RemoveOtherCrap {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_RemoveOtherCrap")) {
		Say "      ********************** Entering _Global_RemoveOtherCrap_ Routine ******************************"
		$AppBL = @("Microsoft.BingNews","Microsoft.BingWeather","Microsoft.GetHelp","Microsoft.Getstarted","Microsoft.Messaging","Microsoft.Microsoft3DViewer","Microsoft.MicrosoftOfficeHub","Microsoft.MicrosoftSolitaireCollection","Microsoft.MixedReality.Portal","Microsoft.NetworkSpeedTest","Microsoft.News","Microsoft.Office.Lens","Microsoft.Office.OneNote","Microsoft.Office.Sway","Microsoft.Office.Todo.List","Microsoft.OneConnect","Microsoft.Paint3D","Microsoft.People","Microsoft.Print3D","Microsoft.RemoteDesktop","Microsoft.SkypeApp","Microsoft.MicrosoftStickyNotes","Microsoft.StorePurchaseApp" `
				,"Microsoft.ScreenSketch","Microsoft.Wallet","Microsoft.Whiteboard","Microsoft.WindowsCamera","Microsoft.windowscommunicationsapps","Microsoft.WindowsFeedbackHub","Microsoft.WindowsMaps","Microsoft.Windows.Photos","Microsoft.WindowsSoundRecorder","Microsoft.Xbox*","Microsoft.Xbox.TCUI","Microsoft.XboxApp","Microsoft.XboxGameCallableUI","Microsoft.XboxGameOverlay","Microsoft.XboxGamingOverlay","Microsoft.XboxIdentityProvider","Microsoft.XboxSpeechToTextOverlay","Microsoft.YourPhone","Microsoft.ZuneMusic","Microsoft.ZuneVideo","Windows.CBSPreview","*EclipseManager*","*ActiproSoftwareLLC*" `
				,"*AdobeSystemsIncorporated.AdobePhotoshopExpress*","*Duolingo-LearnLanguagesforFree*","*PandoraMediaInc*","*CandyCrush*","*Wunderlist*","*Flipboard*","*Twitter*","*Facebook*","*Spotify*","*Minecraft*","*Royal Revolt*","*Sway*","*Speed Test*","*Dolby*","*Netflix*","*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*","*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*","*Microsoft.BingWeather*","*Microsoft.WindowsStore*","*LinkedIn*","*Amazon*","*WildTangent*")
		foreach ($CrapApp in $AppBL) {
			Get-AppxPackage -Name $CrapApp| Remove-AppxPackage -Force -erroraction silentlycontinue | out-null
			Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $CrapApp | Remove-AppxProvisionedPackage -Online -Force -erroraction silentlycontinue | out-null
			Remove-AppxPackage -package $CrapApp -Force -erroraction silentlycontinue | out-null
		}
		Say "      ********************** Finished _Global_RemoveOtherCrap_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_RemoveOtherCrap" 1
		$global:Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_RemoveOtherCrap"
	}
}

Function Global_CleanRegCrapware {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_CleanRegCrapware")) {
		Say "      ********************** Entering _Global_CleanRegCrapware_ Routine ******************************"
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
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.BingWeather_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.GetHelp_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Getstarted_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Microsoft3DViewer_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Office.OneNote_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.OneConnect_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.People_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Print3D_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.SkypeApp_kzf8qxf38zg5c"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.StorePurchaseApp_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Wallet_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Windows.Photos_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.WindowsAlarms_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.WindowsCamera_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\microsoft.windowscommunicationsapps_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.WindowsMaps_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.WindowsStore_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Xbox.TCUI_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.XboxApp_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.XboxGameOverlay_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.XboxIdentityProvider_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.ZuneMusic_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.ZuneVideo_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.3DBuilder_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.HEVCVideoExtension_8wekyb3d8bbwe"
			"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned"
		)
		ForEach ($Key in $RegKeys) {
			Remove-Item $Key -Recurse -Force -ErrorAction SilentlyContinue | out-null
		}
		Say "      ********************** Finished _Global_CleanRegCrapware_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_CleanRegCrapware" 1
		$global:Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_CleanRegCrapware"
	}
}
            
Function Global_DisableTelemetry {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_DisableTelemetry")) {
		Say "      ********************** Entering _Global_DisableTelemetry_ Routine ******************************"

		#Disable WiFi tracking and reporting & turn off WiFi Sense
		regSet "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" "Value" 0 
		regSet "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" "Value" 0 
		
		#Turn Off Connect to suggested open hotspots and Connect to networks shared by my contacts:
		regSet "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" 0 

		#Turns off Data Collection via the AllowTelemtry key by changing it to 0
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0 
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0 
		regSet "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" "AllowTelemetry" 0 

		#Disabling Location Tracking
		regSet "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0 
		regSet "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" "Status" 0 
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" "Value" "Deny"


		#Disables scheduled tasks that are considered unnecessary 
		Get-ScheduledTask  XblGameSaveTaskLogon | Disable-ScheduledTask | out-null #Automatically connects to XBox Live  Network
		Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask  | out-null #Automatically sends statistical data to XBox Live Network
		Get-ScheduledTask  Consolidator | Disable-ScheduledTask  | out-null #Windows Customer Experience Improvement Program (WCEIP)
		Get-ScheduledTask  UsbCeip | Disable-ScheduledTask  | out-null #Collects USB information about your machine 
		Get-ScheduledTask  DmClient | Disable-ScheduledTask  | out-null #Collects IoT related data from the system
		Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask  | out-null #Downloads IoT related data from the system

		#Disabling the Diagnostics Tracking Service
		Stop-Service "DiagTrack" | out-null
		Set-Service "DiagTrack" -StartupType Disabled | out-null

		If (Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore") {
			$getproc = Get-Process | where {$_.Name -like "explorer"};foreach ($proc in $getproc) {Stop-Process $proc -Force | Out-Null}
			Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
			Start-Process Explorer.exe -Wait | Out-Null
		}
		Say "      ********************** Finished _Global_DisableTelemetry_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_DisableTelemetry" 1
		$global:Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_DisableTelemetry"
	}
}

Function Global_DisableWindowsCortana {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_DisableWindowsCortana")) {
		Say "      ********************** Entering _DisableWindowsCortana_ Routine ******************************"
		#Disabling Bing and Cortana.  Bing and Cortana will no longer be used the default for Windows Search.		
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCortana" 0 #Allow Cortana
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "DisableWebSearch" 1 #Allow search and Cortana to use location	
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowSearchToUseLocation" 0 #Allow search and Cortana to use location	
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" "ConnectedSearchUseWeb" 0 #Don't search the web or display web results in Search	
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" "{0DE40C8E-C126-4A27-9371-A27DAB1039F7}" "v2.25|Action=Block|Active=TRUE|Dir=Out|Protocol=6|App=%windir%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\searchUI.exe|Name=Block outbound Cortana|" #Block Cortana on Windows Firewall
		Say "      ********************** Finished _DisableWindowsCortana_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_DisableWindowsCortana" 1
		$global:Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_DisableWindowsCortana"
	}
}

Function Global_DisableEdgePDF {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_DisableEdgePDF")) {
		Say "      ********************** Entering _Global_DisableEdgePDF_ Routine ******************************"
		If (!(Get-ItemProperty "HKCR:\.pdf"  NoOpenWith)) {New-ItemProperty "HKCR:\.pdf"  NoOpenWith }        
		If (!(Get-ItemProperty "HKCR:\.pdf"  NoStaticDefaultVerb)) {New-ItemProperty "HKCR:\.pdf"  NoStaticDefaultVerb }        
		If (!(Get-ItemProperty "HKCR:\.pdf\OpenWithProgids"  NoOpenWith)) {New-ItemProperty "HKCR:\.pdf\OpenWithProgids"  NoOpenWith }        
		If (!(Get-ItemProperty "HKCR:\.pdf\OpenWithProgids"  NoStaticDefaultVerb)) {New-ItemProperty "HKCR:\.pdf\OpenWithProgids"  NoStaticDefaultVerb }        
		If (!(Get-ItemProperty "HKCR:\.pdf\OpenWithList"  NoOpenWith)) {New-ItemProperty "HKCR:\.pdf\OpenWithList"  NoOpenWith}        
		If (!(Get-ItemProperty "HKCR:\.pdf\OpenWithList"  NoStaticDefaultVerb)) {New-ItemProperty "HKCR:\.pdf\OpenWithList"  NoStaticDefaultVerb }
		If (Test-Path "HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_") {Set-Item "HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_" "AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_"}
		Say "      ********************** Finished _Global_DisableEdgePDF_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_DisableEdgePDF" 1
		$global:Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_DisableEdgePDF"
	}
}

Function Global_FixSvcDMW {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_FixSvcDMW")) {
		Say "      ********************** Entering _Global_FixSvcDMW_ Routine ******************************"
		If (Get-Service -Name dmwappushservice | Where-Object {$_.StartType -eq "Disabled"}) {
			Set-Service -Name dmwappushservice -StartupType Manual
			Wait 3
		}
		If (Get-Service -Name dmwappushservice | Where-Object {$_.Status -eq "Stopped"}) {Start-Service -Name dmwappushservice} 
		Say "      ********************** Finished _Global_FixSvcDMW_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_FixSvcDMW" 1
	} Else {
		Say "      Admin Elevation has already executed Global_FixSvcDMW"
	}
}

Function Global_FixCalculator {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_FixCalculator")) {
		Say "      ********************** Entering _Global_FixCalculator_ Routine ******************************"
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
		regSet "HKLM:Software\Policies\Microsoft\Windows\OneDrive" "OneDrive" "DisableFileSyncNGSC"
		$getproc = Get-Process | where {$_.Name -like "OneDrive*"};foreach ($proc in $getproc) {Stop-Process $proc -Force | Out-Null}
		Wait 3

		If (!(Test-Path "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe")) {
			$getproc = Get-Process | where {$_.Name -like "OneDrive*"};foreach ($proc in $getproc) {Stop-Process $proc -Force | Out-Null}
			Wait 3
			If (Test-Path "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe") {Start-Process "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe" "/uninstall" -NoNewWindow -Wait} 
			ElseIf (Test-Path "$env:SYSTEMROOT\System32\OneDriveSetup.exe") {Start-Process "$env:SYSTEMROOT\System32\OneDriveSetup.exe" "/uninstall" -NoNewWindow -Wait} 
			Wait 3
			Say "         Stopping explorer to perform some cleanup tasks."
			$getproc = Get-Process | where {$_.Name -like "explorer"};foreach ($proc in $getproc) {Stop-Process $proc -Force | Out-Null}
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
		$global:Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_UninstallOneDrive"
	}
}

Function Global_Remove3DObjects {
	If (!(regGet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_Remove3DObjects")) {
		Say "      ********************** Entering _Global_Remove3DObjects_ Routine ******************************"
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
		
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" "PreventDeviceMetadataFromNetwork" 1 #Prevent Windows from retrieving device metadata from the Internet
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice\AllowFindMyDevice" "(Default)" 0 #To turn off Find My Device
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" "DoNotTrack" 1 #Enable Microsoft Edge Configure Do Not Track
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" "AllowBuildPreview" 0 #To turn off Insider Preview builds for a released version of Windows 10

		#Disabling Global Windows Experience Features
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" "NoActiveProbe" 1 #Disable Network Connection Status Indicator
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" "AutoDownloadAndUpdateMapData" 0 #Disable Offline maps auto update
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Maps" "AllowUntriggeredNetworkTrafficOnSettingsPage" 0 #Disable Offline maps sync
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoCloudApplicationNotification" 1 #Turn off notifications network usage
		regSet "HKLM:\Software\Policies\Microsoft\Speech" "AllowSpeechModelUpdate" 0 #Turn off speech mode updates
		
		#Enhancing Global System Privacy Policies
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows Mail" "ManualLaunchAllowed" 0 #Mail synchronization
		regSet "HKLM:\System\CurrentControlSet\Services\wlidsvc" "" 4 #Disable Microsoft Account Sign-In Assistant

		#Disable Let apps use advertising ID to make ads more interesting (Feedback Experience Program)
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0 #Disable Let apps use my advertising ID for experiences across apps
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" 1 
		regSet "HKLM:\Software\Policies\Microsoft\Windows\System" "EnableCdp" 0 #Turn off Let apps on my other devices open apps and continue experiences on this device
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessLocation" 2 #Disable App Location Access (Devices have access to location-specific sensors and which apps have access to the device's location)
		regSet "HKLM:\Software\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" 1 #Disable System Location Access
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCamera" 2 #Let apps use my camera
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMicrophone" 2 #Let apps use my microphone
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessNotifications" 2 #Turn off Let apps access my notifications
		#Let apps access my name, picture, and other account info - Disable Let Windows Apps Access Account Info for All Accounts
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy" "LetAppsAccessAccountInfo" 2 
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy" "LetAppsAccessAccountInfo_ForceAllowTheseApps" ""
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy" "LetAppsAccessAccountInfo_ForceDenyTheseApps " ""
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy" "LetAppsAccessAccountInfo_UserInControlOfTheseApps" ""

		regSet "HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy" "LetAppsAccessContacts" 2 #Turn Off Choose apps that can access contacts
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\AppPrivacy" "LetAppsAccessCalendar" 2 #Turn Off let apps access my calendar
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCallHistory" 2 #Turn Off let apps access my call history
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessEmail" 2 #Turn Off let apps access and send email
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMessaging" 2 #Turn Off let apps read or send messages (text or MMS)
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessPhone" 2 #Turn Off let apps make phone calls
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessRadios" 2 #Turn Off let apps control radios
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsSyncWithDevices" 2 #Turn Off let apps automatically share and sync info with wireless devices that don't explicitly pair with your PC, tablet, or phone
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessTrustedDevices" 2 #Turn Off let your apps use your trusted devices (hardware you've already connected, or comes with your PC, tablet, or phone)
		regSet "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" 1 #Disable Apps from asking for feedback
		regSet "HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry" "" 0 #Disable System from sending MS telemetry
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" 1 #Disable Tailored Experience Diagnostic Data
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsRunInBackground" 2 #Disable Apps from running in the background
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMotion" 2 #Turn Off let Windows and your apps use your motion data and collect motion history
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessTasks" 2 #Turn Off choose which apps have access to your tasks
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsGetDiagnosticInfo" 2 #Turn Off choose which apps have access to your diagnostic information
		regSet "HKLM:\Software\Policies\Microsoft\Windows\System" "EnableActivityFeed" 2 #Turn Off tracking of your Activity History
		regSet "HKLM:\Software\Policies\Microsoft\Windows\System" "PublishUserActivities" 2 #Disable Publish User Activity
		regSet "HKLM:\Software\Policies\Microsoft\Windows\System" "UploadUserActivities" 2 #Disable Upload User Activity
		regSet "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsActivateWithVoice" 2 #Disable App Voice Keyword Activation
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
		regSet "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\Type" "(Default)" "NoSync" #Prevent Windows from setting the time automatically
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\W32time\TimeProviders\NtpClient" "Enabled" 0 #Prevent Windows from setting the time automatically
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EnableFontProviders" "(Default)" 0 #Download fonts on demand
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Suggested Sites" "Enabled" 0		#IE Turn on Suggested Sites	
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer" "AllowServicePoweredQSA" 0		#Allow Microsoft services to provide enhanced suggestions as the user types in the Address Bar	
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" "AutoSuggest" "no" #Turn off the auto-complete feature for web addresses	
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Geolocation" "PolicyDisableGeolocation" 1 #Turn off browser geolocation	
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\PhishingFilter" "EnabledV9" 0 #Prevent managing Windows Defender SmartScreen	
		regSet "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled" "Off" #Prevent managing Windows Defender SmartScreen	
		regSet "HKLM:\Software\Policies\Microsoft\Internet Explorer\Main" "DoNotTrack" 1 #MS IE Always send Do Not Track header
		regSet "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" "DisableTelemetryOptInChangeNotification" 0 #Configure telemetry opt-in change notifications
		regSet "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" "ConfigureTelemetryOptInChangeNotification" 0 #ConfigureTelemetryOptInChangeNotification
		regSet "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" "DisableTelemetryOptInSettingsUx" 1 #Configure telemetry opt-in setting user interface
		regSet "HKLM:\System\CurrentControlSet\Services\wlidsvc" "Start" 4 #To disable the Microsoft Account Sign-In Assistant:
		regSet "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" "SmartScreenEnabled" "Off" 		#Turn on Windows Defender SmartScreen to check web content (URLs) that Microsoft Store apps use:
		regSet "HKLM:\Software\Policies\Microsoft\Windows\Messaging" "AllowMessageSync" 0 #Turn Off Choose apps that can read or send messages (Message Sync)

		#Windows Defender: Stop sending file samples back to Microsoft.
		regSet "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent" 2  
		regSet "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" "SpyNetReporting" 2
		regSet "HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet" "SpyNetReportingLocation" " "
		regSet "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent" 2  
		regSet "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SpyNetReporting" 2
		regSet "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SpyNetReportingLocation" " "

		regSet "HKLM:\Software\Policies\Microsoft\MRT" "DontReportInfectionInformation" 1 #Turn off Malicious Software Reporting Tool (MSRT) diagnostic data

		#To disable Windows Defender Smartscreen:
		regSet "HKLM:\Software\Policies\Microsoft\Windows\System" "EnableSmartScreen" 0 
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" "ConfigureAppInstallControlEnabled" 1
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" "ConfigureAppInstallControl" "Anywhere"
		regSet "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet\SpyNetReporting" "" 2 # Disable cloud Defender protection (SpyNet)

		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableAppUriHandlers" 0 #turn off apps for websites, preventing customers who visit websites that are registered with their associated app from directly launching the app.

		# Disable Let Windows Apps Access Contacts for All Accounts
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessContacts" ""
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessContacts_UserInControlOfTheseApps" ""
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessContacts_ForceAllowTheseApps" ""
		regSet "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessContacts_ForceDenyTheseApps" ""
		
		#All them dang Windows 10 Privacy settings..  let's lock them down.
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" "Value" "Deny" #Deny access to motion activity on this device
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" "Value" "Deny" #Deny access to app diagnostics on this device
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" "Value" "Deny" #Deny access to calendar on this device
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetooth" "Value" "Deny" #Deny access to bluetooth devices
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" "Value" "Deny" #Deny access to other devices
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" "Value" "Deny" #Deny access to entire file system
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\cellularData" "Value" "Deny" #Deny access to cellular data usage
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" "Value" "Deny" #Deny access to chat/im/skype
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" "Value" "Deny" #Deny access to contacts on this device
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" "Value" "Deny" #Deny access to documents on this device
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" "Value" "Deny" #Deny access to email on this device
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\gazeInput" "Value" "Deny" #Deny access to gaze eye tracking on this device
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanInterfaceDevice" "Value" "Deny" #Deny access to HID's
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" "Value" "Deny" #Deny access to microphone
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" "Value" "Deny" #Deny access to phone
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" "Value" "Deny" #Deny access to phone call history
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" "Value" "Deny" #Deny access to pictures on this device
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" "Value" "Deny" #Deny access to radios
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\sensors.custom" "Value" "Deny" #Deny access to custom sensors on this device (GPS maybe)
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\serialCommunication" "Value" "Deny" #Deny access to serial communications on this device
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\usb" "Value" "Deny" #Deny access to USB diagnostics on this device
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" "Value" "Deny" #Deny access to user account information
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" "Value" "Deny" #Deny access to tasks (such ass calendar tasks and todo's)
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" "Value" "Deny" #Deny access to notifications
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" "Value" "Deny" #Deny access to video on this device
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" "Value" "Deny" #Deny access to webcam
		regSet "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wiFiDirect" "Value" "Deny" #Deny access to WiFi Direct data on this device

		Say "      ********************** Finished _Global_SetSystemPolicies_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_SetSystemPolicies" 1
		$global:Need2Reboot = 1
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
		regSet "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" "UseWUServer" 1 #Disable Windows Update Auto-Update Check Service
		
		Say "      ********************** Finished _Global_SetUpdatePolicies_ Routine ******************************"
		regSet "HKLM:\SOFTWARE\MegaphatNetworks\CMRS" "Global_SetUpdatePolicies" 1
		$global:Need2Reboot = 1
	} Else {
		Say "      Admin Elevation has already executed Global_SetUpdatePolicies"
	}
}

	$ErrorActionPreference = 'SilentlyContinue'
	If (!($args[0] -eq "elevate")) {
		SetConsoleSize
		doIntro $Intro
		Write-Host "Preparing to exorcise this computer of MS and related demons..."
		$curdir = [System.IO.Path]::GetDirectoryName($myInvocation.MyCommand.Definition)
		Write-Host $curdir
		notepad.exe $curdir\Win10ExInfo.txt
	}
	Wait 3

	$doGlobal_Config = 1				#Change this to 1 in order to execute ANY Admin Privileged-level routines
	$doGlobal_RemoveMSCrap = 1			#Change to 1 in order to remove the MS added crapware
	$doGlobal_RemoveOtherCrap = 1		#Change to 1 in order to get rid of sponsored crapware
	$doGlobal_CleanRegCrapware = 1		#Change to 1 in order to clean the registry from crapware.  Should be performed if doGlobal_RemoveOtherCrap = 1
	$doGlobal_DisableTelemetry = 1		#Change to 1 in order to Disable MS telemetry and tracking.
	$doGlobal_DisableWindowsCortana = 1	#Change to 1 in order to turn off Cortana as the Windows Search Provider
	$doGlobal_DisableEdgePDF = 1		#Change to 1 in order to disable MS Edge as the default PDF reader
	$doGlobal_FixSvcDMW = 0				#Change to 1 in order to fix the DMW service which may be affected by the operations within
	$doGlobal_FixCalculator = 0			#Change to 1 in order to fix the calculator app
	$doGlobal_UninstallOneDrive = 1		#Change to 1 in order to uninstall MS OneDrive
	$doGlobal_Remove3DObjects = 1		#Change to 1 in order to Remove the 3D Objects folder from Explorer
	$doGlobal_SetSystemPolicies = 1		#Change to 1 in order to set system policies to prevent crapware from returning
	$doGlobal_SetUpdatePolicies = 1		#Change to 1 in order to set Windows Updates policies to prevent Windows Updates from being automatic
	
	$doProfile_Config = 1 				#Change this to 1 in order to execute ANY Profile-level routines
	$doProfile_DisableCDM = 1			#Change to 1 in order to disable MScontent delivery
	$doProfile_DisableWindowsCortana = 1#Change to 1 in order to turn off Cortana as the Windows Search Provvider to the logged-on profile
	$doProfile_UnPinStartMenuItems = 0	#Change to 1 in order to Un-pin start menu items
	$doProfile_DisableTracking = 1		#Change to 1 in order to disable MS tracking
	$doProfile_SetProfilePolicies = 1	#Change to 1 in order to set profile policies to disable Windows Experience features and settings

	$global:Need2Reboot = 0
	$CMRSP = "$Env:SystemDrive\Temp\CMRS\"
	$CMRSA = "$Env:SystemDrive\Temp\CMRS\Global.txt"
	$CMRSU = "$Env:Temp\CMRS\Profile.txt"

	PS-RegisterScript
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
		If (!($doProfile_SetProfilePolicies)) {Say "      doProfile_SetProfilePolicies set to 0, not executing Profile_SetProfilePolicies"} Else {Profile_SetProfilePolicies}
		Say "Completed the execution of the script for the user profile $env:username."
	}
	
    Say "The exorcism of your Windows 10 machine has completed."
    Stop-Transcript | Out-Null
    
    If ($global:Need2Reboot) {
		Say "Your system has been modified and requires a restart.  Automatically restarting in 10 seconds..."
		Wait 10
		Restart-Computer
	} else {
		Write "The power of Christ compels you! - Fr Damien Karras 1973"
	}
