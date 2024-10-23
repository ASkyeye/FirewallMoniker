# FirewallMoniker
A C# implementation that will disable the Windows Firewall from a non elevated context of an admin user by modifying the PEB and using a COM Elevation Moniker (Elevation:Administrator!new:).

FireWallMoniker utilizes COM interop to interact with the Windows Firewall through the INetFwPolicy2 interface. 

* E2B3C97F-6AE1-41AC-817A-F6F92166D7DD - HNetCfg.FwPolicy2 - C:\Windows\system32\FirewallControlPanel.dll,-12122

* 98325047-C671-4174-8D81-DEFCD3F03186 - INetFwPolicy2


# Notes

* User needs to be part of admin group. Can execute from non elevated session.
* Activity generates Event 2082 under Microsoft-Windows-Windows Firewall With Advanced Security/Firewall with modifying application ```C:\Windows\SysWOW64\dllhost.exe```

# Reading Material
* Sample from MSDN can be found here: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ics/c-disabling-windows-firewall?redirectedfrom=MSDN

* More about the COM elevation moniker:  https://learn.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker

* Original article at https://3gstudent.github.io/%E9%80%9A%E8%BF%87COM%E7%BB%84%E4%BB%B6NetFwPolicy2%E8%B6%8A%E6%9D%83%E5%85%B3%E9%97%AD%E9%98%B2%E7%81%AB%E5%A2%99

# Credits

Original idea and implementation came from https://github.com/3gstudent/Homework-of-C-Language/blob/e21cb129e15fd2186bd8ec1310bcc23c38ab209b/DisableFirewall.cpp

Shouts to @trickster012 for nerding out :)

Lefty (@lefterispan) 2024 - Nettitude RT
