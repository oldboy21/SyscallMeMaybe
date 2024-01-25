; bello code for syscall 

.data
EXTERN SSN: DWORD
EXTERN SYSCALLADDR: QWORD

.code 
ZwAllocateVirtualMemory PROC
	mov r10, rcx
	mov eax, SSN
	jmp SYSCALLADDR
ZwAllocateVirtualMemory ENDP

ZwWriteVirtualMemory PROC
	mov r10, rcx
	mov eax, SSN
	jmp SYSCALLADDR
ZwWriteVirtualMemory ENDP

ZwProtectVirtualMemory PROC
	mov r10, rcx
	mov eax, SSN
	jmp SYSCALLADDR
ZwProtectVirtualMemory ENDP

ZwCreateThreadEx PROC
	mov r10, rcx
	mov eax, SSN
	jmp SYSCALLADDR
ZwCreateThreadEx ENDP


end