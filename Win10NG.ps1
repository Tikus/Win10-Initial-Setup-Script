##########
# Win 10 / Server 2016 / Server 2019 Initial Setup Script - Main execution loop
# Author: Disassembler <disassembler@dasm.cz>
# Version: v3.6, 2019-01-28
# Source: https://github.com/Disassembler0/Win10-Initial-Setup-Script
##########

# Relaunch the script with administrator privileges
Function RequireAdmin {
	If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
		Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -Verb RunAs
		Exit
	}
}

$tweaks = @()
$PSCommandArgs = @()

Function AddOrRemoveTweak($tweak) {
	If ($tweak[0] -eq "!") {
		# If the name starts with exclamation mark (!), exclude the tweak from selection
		$script:tweaks = $script:tweaks | Where-Object { $_ -ne $tweak.Substring(1) }
	} ElseIf ($tweak -ne "") {
		# Otherwise add the tweak
		$script:tweaks += $tweak
	}
}

# Cleanup all resourcesFunction CleanUp {
Function Cleanup(){
	Write-Output "Cleaning up ..."
	[gc]::collect()	
	if (test-path -path "HKEY_USERS\DefaultUser"){
		echo "Unloading HKU\DefaultUser"
		reg unload HKU\DefaultUser
	}	

	$hkcu_value = Get-PSDrive -Name HKCU -ErrorAction SilentlyContinue | select -ExpandProperty Root

	if ( $hkcu_value -ne "HKEY_CURRENT_USER"){
		echo "Restoring HKCU to HKEY_CURRENT_USER"
    	Remove-PSDrive -name HKCU -ErrorAction SilentlyContinue
    	New-PSDrive -name "HKCU" -ROOT "HKEY_CURRENT_USER" -PSProvider Registry -Scope Global | Out-null
	}
}

# Redirect HKCU to HKEY_USERS/$current_user_sid
$current_user_sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
if ($current_user_sid){
	Remove-PSDrive -name HKCU -ErrorAction SilentlyContinue
	echo "Relinking HKCU to HKEY_USERS/$current_user_sid"
	New-PSDrive -Name "HKCU" -PSProvider Registry -Root "HKEY_USERS\$current_user_sid" -Scope Global | Out-Null
}

# Parse and resolve paths in passed arguments
$i = 0
While ($i -lt $args.Length) {
	If ($args[$i].ToLower() -eq "-include") {
		# Resolve full path to the included file
		$include = Resolve-Path $args[++$i]
		$PSCommandArgs += "-include `"$include`""
		# Import the included file as a module
		Import-Module -Name $include
	} Elseif ($args[$i].ToLower() -eq "-DefaultUser") {
		echo "Default User selected"
		RequireAdmin	
		reg load HKEY_USERS\DefaultUser "$env:systemDrive\users\Default\NTUSER.DAT" | Out-Null
		echo "Relinking HKCU to HKEY_USERS\DefaultUser"
		Remove-PSDrive -name HKCU -ErrorAction SilentlyContinue
		New-PSDrive -Name "HKCU" -PSProvider Registry -Root "HKEY_USERS\DefaultUser" -Scope Global
	} ElseIf ($args[$i].ToLower() -eq "-preset") {
		# Resolve full path to the preset file
		$preset = Resolve-Path $args[++$i]
		$PSCommandArgs += "-preset `"$preset`""
		# Load tweak names from the preset file
		Get-Content $preset -ErrorAction Stop | ForEach-Object { AddOrRemoveTweak($_.Split("#")[0].Trim()) }
	} Else {
		$PSCommandArgs += $args[$i]
		# Load tweak names from command line
		AddOrRemoveTweak($args[$i])		
	}
	$i++
}

# Call the desired tweak functions
$tweaks | ForEach-Object { Invoke-Expression $_ }

Cleanup