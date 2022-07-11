function AddUser($username,$password){
	if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
		$computer=Get-WMIObject  Win32_ComputerSystem
		$computername = $computer.name
		$username = $username
		$password = $password
		$desc = 'Local admin account'
		$computer = [ADSI]"WinNT://$computername,computer"
		$user = $computer.Create("user", $username)
		$user.SetPassword($password)
		$user.Setinfo()
		$user.description = $desc
		$user.setinfo()
		$user.UserFlags = 65536
		$user.SetInfo()
		$group = [ADSI]("WinNT://$computername/administrators,group")
		$group.add("WinNT://$username,user")
		$dc=Get-WmiObject -Class Win32_UserAccount  | find ": $username"
		if($dc.Length -eq 0){
			Write-Host "[-] Add user:$username failed"
		}else{
			Write-Host "[+] Add user:$username Sucess"
			net user $username
		}
	}else{
		Write-Host "[-] Not Administrator power"
	}
}