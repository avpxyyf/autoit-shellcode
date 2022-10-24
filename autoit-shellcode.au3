#AutoIt3Wrapper_UseX64=n
#RequireAdmin
#include <WinAPI.au3>
#include <Memory.au3>
#include <String.au3>

;change this according to your test program's name
$PROCESS_NAME = "mem_test.exe"

; open a handle to kernel32
Global $Kernel32 = DllOpen("Kernel32.dll")

_main()

Func _main()
	; get the PID of the process
	$PID = ProcessExists($PROCESS_NAME)

	; if PID = 0 exit
	if (Not $PID) Then Return MsgBox(64, "Shellcode Test", "Could not find the process.")

	; open a handle to process with PROCESS_ALL_ACCESS (0x1F0FFF)
	$PROCESS = _WinAPI_OpenProcess(0x1F0FFF, False, $PID)
	if not $PROCESS then MsgBox(16, "Shellcode Test", "Could not open a handle to the process.")

	; get user input for 3 parameters
	$P1 = InputBox("Shellcode Test", "Enter the first parameter: ", "")
	$P2 = InputBox("Shellcode Test", "Enter the second parameter: ", "")
	$P3 = InputBox("Shellcode Test", "Enter the third parameter: ", "")

	; if no input is given, exit
	If Not $P1 Or Not $P2 Then Exit
	$P1 = Dec(Hex($P1))
	$P2 = Dec(Hex($P2))
	$P3 = Dec(Hex($P3))

	; read the address of the remote function
	$function_addr = "0x" & FileRead("addr.txt")

	; initialize shellcode as a hex string
	$shellcode = "0x" & _
	"FF35 00000000" & _  ; push DWORD PTR 0x0 (parameter 3)
	"FF35 00000000" & _	 ; push DWORD PTR 0x0 (parameter 2)
	"FF35 00000000" & _  ; push DWORD PTR 0x0 (parameter 1)
	"B8   00000000" & _  ; push eAX, remote_function
	"FFD0" & _			 ; call eAX
	"5B" & _             ; pop eBX
	"5A" & _             ; pop eDX
	"59" & _             ; pop eCX
	"C3" & _             ; ret
	"00000000000000000000000000000000"

	; remove all spaces
	$shellcode = StringReplace($shellcode, " ", "")

	; data size = largest null byte padding / 2
	$DATA_SIZE = StringLen(StringRegExp($shellcode, "([00]*)(?<=\Z)", 1)[0]) / 2

	; remove data size from total size
	$SHELLCODE_SIZE = BinaryLen($SHELLCODE) - $DATA_SIZE

	; create a byte array
	$shellcodeBuffer = DllStructCreate("byte["&BinaryLen($SHELLCODE)&"];")

	; fill the byte array
	DllStructSetData($shellcodeBuffer, 1, $SHELLCODE)

	; allocate memory for the shellcode
	$hRemoteCode = _MemVirtualAllocEx($PROCESS, 0, DllStructGetSize($shellcodeBuffer), $MEM_COMMIT + $MEM_RESERVE, $PAGE_EXECUTE_READWRITE) ; allocate space to the memory

	; if the program is unable to allocate memory, exit
	if Not $hRemoteCode Then Return MsgBox(16, "Shellcode Test", "Could not allocate memory for the shellcode")

	; get the sizes of the parameters (kinda useless with int)
	$P1_SIZE = BinaryLen($P1)
	$P2_SIZE = BinaryLen($P2)
	$P3_SIZE = BinaryLen($P3)

	; our data begin at the end of the shellcode
	$P1_OFFSET = $SHELLCODE_SIZE	   ; base of P1 = first byte of DATA
	$P2_OFFSET = $P1_OFFSET + $P1_SIZE ; base of P1 + size of P1 = base of P2
	$P3_OFFSET = $P2_OFFSET + $P2_SIZE ; base of P2 + size of P2 = base of P3

	; the address of each parameter is BASE + parameter_x offset
	$p1_addr = $hRemoteCode + $P1_OFFSET
	$p2_addr = $hRemoteCode + $P2_OFFSET
	$P3_addr = $hRemoteCode + $P3_OFFSET

	; copy addresses
	dllstruct_cpy($shellcodeBuffer, dllstruct_indexof($shellcodeBuffer, 0xFF, 0x35)    + 1, $p1_addr, 4)
	dllstruct_cpy($shellcodeBuffer, dllstruct_indexof($shellcodeBuffer, 0xFF, 0x35, 2) + 1, $p2_addr, 4)
	dllstruct_cpy($shellcodeBuffer, dllstruct_indexof($shellcodeBuffer, 0xFF, 0x35, 3) + 1, $P3_addr, 4)
	dllstruct_cpy($shellcodeBuffer, dllstruct_indexof($shellcodeBuffer, 0xB8), $function_addr, 4) ; already inverted

	; copy data
	dllstruct_cpy($shellcodeBuffer, $P1_OFFSET, $P3, $P3_SIZE)
	dllstruct_cpy($shellcodeBuffer, $P2_OFFSET, $P2, $P2_SIZE)
	dllstruct_cpy($shellcodeBuffer, $P3_OFFSET, $P1, $P1_SIZE)

	; write the shellcode to the allocated memory
	Local $written
    _WinAPI_WriteProcessMemory ($PROCESS, $hRemoteCode,DllStructGetPtr($shellcodeBuffer), DllStructGetSize($shellcodeBuffer),$written)

	; create a thread to call the shellcode
	$call = DllCall($Kernel32, "int", "CreateRemoteThread", "ptr", $PROCESS, "ptr", 0, "int", 0,"ptr", $hRemoteCode,"ptr", 0,"int", 0,"dword*", 0)
	if UBound($call) < 1 Then Return MsgBox(16, "Shellcode Test", "Could not create the remote thread.")

	; wait until the thread exits
	_WinAPI_WaitForSingleObject($call[0])

	; free the allocated memory
	_MemVirtualFreeEx($PROCESS, $hRemoteCode, 0, $MEM_RELEASE)

	; start over
	$x = MsgBox(BitOR(64, 4), "Shellcode Test", "Operation completed with no errors. Do you want to go again?")
	if $x = 6 Then _main()
EndFunc

DllClose($Kernel32)

; copy data to byte array struct
Func dllstruct_cpy(ByRef $struct, $offset, $data, $size = BinaryLen($data))
	; if data = binary then use a byte array instead of dword
	Switch VarGetType($data)
		Case "Binary"
			$type = "byte["&BinaryLen($data)&"]"
		case Else
			$type = "DWORD"
	EndSwitch

	; forced "type casting" - experimental method
	$t_1 = DllStructCreate($type & " t")
	DllStructSetData($t_1, 1, $data)
	$t_struct = DllStructCreate("byte["&BinaryLen($data)&"]")
	DllStructSetData($t_struct, 1, DllStructGetData($t_1, 1))
	$t_data = DllStructGetData($t_struct, 1)

	; if the experimental method returns 0, use the stable one
	if ($t_data = 0) Then
		If IsString($data) Then
			DllStructSetData($t_struct, 1, StringToBinary($data))
		Else
			DllStructSetData($t_struct, 1, $data)
		endif
	EndIf

	; replace bytes from (BASE + OFFSET) to (BASE + OFFSET + SIZE) with the new bytedata
	For $i = 1 to $size
		DllStructSetData($struct, 1, DllStructGetData($t_struct, 1, $i), $offset + $i)
	Next
EndFunc

; get the index of 1 or 2 bytes in the byte array struct
Func dllstruct_indexof(ByRef $struct, $x1, $x2 = 0, $instance = False)
	; current instance = 1
	$s = 1
	; loop through $struct and search for X1
	For $i = 1 To DllStructGetSize($struct)
		; if X1 is found
		if DllStructGetData($struct, 1, $i) = $x1 Then
			; if there is a X2
			if ($x2) Then
				; if X2 is found
				if DllStructGetData($struct, 1, $i+1) = $x2 Then
					; if instance <= s return idx
					If $instance <= $s Then Return $i
					; otherwise increase current instance by 1
					$s = $s + 1
				EndIf
			Else
				; if instance <= s return idx
				If $instance <= $s Then Return $i
				; otherwise increase current instance by 1
				$s = $s + 1
			EndIf
		EndIf
	Next
	; if nothing is found, exit
	MsgBox(16, "Shellcode Test", "Could not find index " & Hex($x1,2) & Hex($x2,2) & @LF)
	Exit
EndFunc



