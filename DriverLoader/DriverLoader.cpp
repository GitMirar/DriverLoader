// DriverLoader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

typedef NTSTATUS (*_NtLoadDriver)(IN PUNICODE_STRING DriverServiceName);

LSTATUS RequirePrivilege(LPCTSTR lpPrivilege) {
	HANDLE hToken;
	BOOL bErr = FALSE;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	bErr = LookupPrivilegeValue(NULL, lpPrivilege, &luid); // lookup LUID for privilege on local system
	if (bErr != TRUE) {
		return -1;
	}
	bErr = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (bErr != TRUE) {
		return -2;

	}

	if (ANYSIZE_ARRAY != 1) {
		return -3;
	}
	tp.PrivilegeCount = 1; // only adjust one privilege
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	bErr = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	// check GetLastError() to check if privilege has been changed
	if (bErr != TRUE || GetLastError() != ERROR_SUCCESS) {
		return -4;
	}
	CloseHandle(hToken);
	return 0;
}

LSTATUS LoadDriver(CONST LPSTR aService, CONST LPSTR aDriver) {
	HKEY hKey;
	HMODULE hNtdll = GetModuleHandleA("Ntdll.dll");
	_NtLoadDriver NtLoadDriver = (_NtLoadDriver) GetProcAddress(hNtdll, "NtLoadDriver");
	LSTATUS ret = -1;

	LSTATUS l = RequirePrivilege(SE_LOAD_DRIVER_NAME);
	if (!l && NtLoadDriver) {
		LPSTR aServiceKey = (LPSTR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH);
		_snprintf_s(aServiceKey, 0x103ui64, 0x103ui64, "System\\CurrentControlSet\\Services\\%s", aService);
		l = RegCreateKeyA(HKEY_LOCAL_MACHINE, aServiceKey, &hKey);
		if (!l) {
			DWORD dwData = 1;
			l = RegSetValueExA(hKey, "Type", 0, REG_DWORD, (BYTE*) &dwData, 4u);
			if (!l) {
				l = RegSetValueExA(hKey, "ErrorControl", 0, REG_DWORD, (BYTE*) &dwData, 4u);
				if (!l) {
					dwData = 3;
					l = RegSetValueExA(hKey, "Start", 0, REG_DWORD, (BYTE*) &dwData , 4u);
					if (!l) {
						LPSTR aDriverKey = (LPSTR) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH);
						l = RegSetValueExA(hKey, "ImagePath", 0, REG_SZ, (const BYTE *)aDriver, strlen(aDriver) + 1);
						if (!l) {
							_snprintf_s(aDriverKey, MAX_PATH, MAX_PATH, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", aService);
							UNICODE_STRING uDriver;
							ANSI_STRING asDriverKey;
							RtlInitAnsiString(&asDriverKey, aDriverKey);
							l = RtlAnsiStringToUnicodeString(&uDriver, &asDriverKey, TRUE);
							if ( !l )
							{
								l = NtLoadDriver(&uDriver);
								ret = l;
								RtlFreeUnicodeString(&uDriver);
								if (!l) {
									l = SHDeleteKeyA(HKEY_LOCAL_MACHINE, aServiceKey);
								}
							}
						}
						HeapFree(GetProcessHeap(), NULL, aDriverKey);
					}
				}
			}
		}
		HeapFree(GetProcessHeap(), NULL, aServiceKey);
	}
	return ret;
}

int _tmain(int argc, _TCHAR* argv[])
{
	USES_CONVERSION;

	if (argc != 3) {
		std::cout << "Please provide the following arguments:" << std::endl;
		std::cout << W2A(argv[0]) << " <path to driver image relative to %WINDIR%> <service name>" << std::endl;
		return -1;
	}

	LPSTR lpDriverImage = W2A(argv[1]);
	LPSTR lpServiceName = W2A(argv[2]);

	DWORD dwErr = LoadDriver(lpServiceName, lpDriverImage);
	if (dwErr != 0) {
		std::cout << "Could not load the driver" << std::endl;
		return -1;
	}

	return 0;
}

