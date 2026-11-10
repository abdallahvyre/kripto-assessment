Set WshShell = CreateObject("WScript.Shell") 
WshShell.Run("""C:\Program Files (x86)\Tor\tor-real.exe"" -f ""C:\Program Files (x86)\Tor\torrc"""),1
Set WshShell = Nothing