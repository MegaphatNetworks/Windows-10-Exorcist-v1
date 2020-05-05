# Cam-Mic-Fix.ps1
## Purpose:
  Windows 10 Exorcist locks a computer down in all respects to make it ultra secure (as much as possible).
  One of the issues that has been brought to my attention is the inability to use Google Hangouts for Audio/Video chats.
  This patch should take care of the issue.

# NTP-Time_Fix.ps1
## Purpose:
  Windows 10 Exorcist locks a computer down in all respects to make it ultra secure (as much as possible).
  This patch allows for a computer to synchronize with a time server.  By default it will synchronize with the pre-defined time
  server within Windows.  If the computer to be executed on is a Domain-level computer, you must perform the following adjustment:
  1. Open the PS1 file with a text Editor such as Notepad++
  2. Locate the function called ## Function Global_SetSystemPolicies
  3. There are 4 regset commands, the first has a #hash mark in front of it, remove the #hash so #regset will only be regset
  4. The second line has no #hash mark in front of it, put one there.
  5. Save the PS1 file and execute with admin rights.
  
# WinUpdates.ps1
## Purpose:
  Windows 10 Exorcist locks a computer down in all respects to make it ultra secure (as much as possible).
  Another issue that has been brought to my attention is the inability to run Windows Updates.
  This patch should take care of the issue.
