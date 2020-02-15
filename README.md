The Windows 10 Exorcist
  by Gabriel Polmar      
  Megaphat Networks      
  www.megaphat.info      

IMPORTANT: This script will make SEVERE changes to your system(s).  That said, let's move on.

INTRODUCTION.  For decades people have called Microsoft the Evil Empire.  I refused to accept this descriptive
term as they were simply a very successful software company which I have worked with, respected and watch 
grow.  In time became beyond wealthy and even greedy but still, I refused to call them by this term.  As the
world turned to Cloud computing, Microsoft introduced to the world the last ever Operating System they claimed
that they will ever make, Windows 10.  Why?  Windows 7 was great in so many ways.  Windows 8 was an aborted
fetus that didn't know when to die and of course, they decided to skip out on Windows 9 since they wanted 
to turn every computing device into a part of their Skynet drone network, but Windows 7 and 8 could not 
achieve this for them.  So now we have the demonically possessed Windows 10 which tracks everything you do and 
using some crazy network witchcraft calls home and tells them everything you do, every site, every email, your
phone data, your fitbit, everything.  Cortana is a wanna-be Succubus that tries to lure you in as if it's Siri but 
nooooo, it's just another tracking device.  

I have noticed a significant decrease in performance since upgrading from Windows 7 x64 SP1 to Windows 10 x64 1909.
My SSD in working more, my CPU cannot rest below 34% where it used to avg about 11%, memory went from 29% to 56% idle
and of course there is the network traffic.  I've watched tons of traffic going to MS related sites for tracking.
This did not happen with Windows 7.  Whether with Wireshark, TCPDump or just my (shout out time) pfSense monitoring, 
MS stuffed a bunch of demons inside of my machine and I wanted them out!  So I did the research and tested on a boatload
of VM's before I was confortable enough to test it on a real machine, then I tested it on my (another shout out) Plex box
and you know what?  The difference is pretty significant.  

BUT WHY?  "There are a bunch of scripts out there that can do this, right?"  Sure.  But I've tried them on sandboxed VM's
and for some reason there are so many privacy settings that were still not resolved.  I have a lot of customers that rely 
on privacy, law firms, medical facilities and privacy is key to their business.  They are small, medium and large businesses 
but Microsoft never gave fore-warning that privacy can only be achieved (so they say) in Windows 10 Enterprise.  So I decided
to give them the power to save themselves a lot of headaches.  My customers are not paying for this.  In fact my customers

So it only took me 2 days to realize that MS has totally screwed Windows 10 users by using their info as data that they
can crunch in their Cloud infrastructure and create sales statistics that they can use for marketing purposes not only 
for themselves, but for their consulting clients as well.  Who knows maybe they will be using their AI platform to compete
with Google at th Ad business.  Maybe they will sell data to Amazon and Alphabet.  So after extensive research I've found 
Powershell scripts that may do it, they may not (they most likely will).  I have a nasty compulsion about properly
formatted and cleanly-written code.  I did not like at all anything I found.  So I tore apart thousands of lines of code 
trying to figure out what their goals were.  I then used those code segments to build a roadmap and begun researching the 
pieces.  Then after a few hundred hours of Google'ing various items, I've collected a massive amount of data.  Now the job 
of reassembling all of this information into a working script.  The first thing was to build a module, which I did do but decided
to keep the core functions within the script since this will be a one-time exorcism (I hope).   

Why do I care?  The idea here is that you paid for Windows, you did not pay for your computer to be their 
private ad delivery service nor did you pay for them to spy on you.  While I am all for profit, I believe that MS has
crossed a line and betrayed the trust of customers and users.  Also I work with a lot of businesses as customers and 
the one thing I have learned is when ANY system calls home without consent of the owner, it has breached a level of 
trust that needs immediate remedy.  

OPERATION.  This script is designed to operated on a multi-user system.  While one user may run the script as admin, 
other users will find that there are still crapware features and tracking telemetry activities happening on their account.       
This script will load once for an administrator, removing all primary crapware.  Each subsequent user who logs on       
the script will then clean their profile as well.  It is up to the system administrator to determine how to implement   
this script and when to discontinue using it. The script will automatically determine if it has been previously executed 
under the logged on user profile as well as administrator to prevent itself from re-execution.

HOME USERS.  Simply run this script on each  of the profiles on the computer, with an Administrator account being the 
first to execute the script and non-Administrators (or other Administrators) thereafter.  

DOMAIN/AD SYSTEMS.  If you are using this in a domain environment, I would suggest including this script in your logon script.
Execution could be as simple as launching from a batch file such as: powershell.exe -ExecutionPolicy Bypass -File .\ThisScript.ps1
Be sure it executes the first time logged in as a Domain Admin.

NON-DOMAIN/AD BUSINESS SYSTEMS: Run the script the same way as listed above for Home Users.

HIPAA Compliancy Notice.  Windows 10 is NOT a HIPAA-compliant OS.  Why?  Because of all of the phone-home telemetry included.
While I have not performed any network sniffing to determine if Windows 10 is actually sending any sensitive data back to MS, 
the mere fact that it phones home with your activity and has access to your information makes it inherently not HIPAA compliant.
Will this script make your system compliant with HIPAA requirements?  To some degree yes.  It will disconnect the OS from having 
access to the sensitive data on your system.  Microsoft has published information on how to make Windows 10 ENTERPRISE EDITION
HIPAA compliant with a set of system tweaks.  All I did is translate that from W10Ent to W10 Home/Pro.  Then I monitored my network 
to see if my OS attempts to contact MS and using pfSense (***LOVE IT***) I was able to monitor all traffic on my systems.  While I
did notice some minor telemetry other than MS Updates, no data was transmitted.


ABOUT THE CODE: Please note that it took about 200 hours of research, 300 hours of coding and testing to get this script working.   
If you find it useful, please give us credit if you clone the script.  If you really want to show your thanks, I would appreciate 
any donation you could make to help pay for the time I spend doing this as well as getting me more coffee to keep me coding!    

USING the script is easy (it just looks hard).  By default the script will act aggressively remove the MS bloated crap.  
To change the settings, open the script in a text editor such as Notepad++ or PN (even the Powershell ISE).  Scroll down to
line 739 and you will see a bunch of variables.  Let's go through them.  Please note that 0 means off and 1 means on.

Global Execution is performed on a machine-level basis.  All changes made here are machine wide and affect all users.  Here are the default settings.
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

Profile Execution is performed on a per-profile basis.  All changes made here are only on the user profile.  Here are the default settings.	
	$doProfile_Config = 1 				#Change this to 1 in order to execute ANY Profile-level routines
	$doProfile_DisableCDM = 1			#Change to 1 in order to disable MScontent delivery
	$doProfile_DisableWindowsCortana = 1#Change to 1 in order to turn off Cortana as the Windows Search Provvider to the logged-on profile
	$doProfile_UnPinStartMenuItems = 0	#Change to 1 in order to Un-pin start menu items
	$doProfile_DisableTracking = 1		#Change to 1 in order to disable MS tracking
	$doProfile_SetProfilePolicies = 1	#Change to 1 in order to set profile policies to disable Windows Experience features and settings

