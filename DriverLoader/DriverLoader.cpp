#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <atlbase.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <Winternl.h>

#pragma comment(lib, "ntdll.lib")

namespace fs = std::filesystem;

typedef NTSTATUS(*_NtLoadDriver)(IN PUNICODE_STRING DriverServiceName);

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

fs::path CopyDriverFile(fs::path sourcePath) {
	auto dstPath = fs::path(R"(C:\Windows\Temp)") / sourcePath.filename();
	std::ifstream  src(sourcePath, std::ios::binary);
	std::ofstream  dst(dstPath, std::ios::binary);
	dst << src.rdbuf();
	return dstPath;
}

LSTATUS LoadDriver(CONST LPSTR aService, CONST fs::path driverPath) {
	USES_CONVERSION;

	HKEY hKey{ 0 };
	HMODULE hNtdll{ 0 };
	_NtLoadDriver NtLoadDriver = nullptr;
	LSTATUS ret{ -1 };
	LSTATUS l{ 0 };
	LPSTR aServiceKey{ 0 };
	DWORD dwData{ 0 };
	LPSTR aDriverKey{ 0 };
	UNICODE_STRING uDriver{ 0 };
	ANSI_STRING asDriverKey{ 0 };
	std::string windowsRelative;
	std::string sDstPath;

	auto dstPath = CopyDriverFile(driverPath);

	hNtdll = GetModuleHandleA("Ntdll.dll");
	if (hNtdll == 0) {
		goto CLEANUP;
	}

	NtLoadDriver = (_NtLoadDriver)GetProcAddress(hNtdll, "NtLoadDriver");
	if (NtLoadDriver == nullptr) {
		goto CLEANUP;
	}

	l = RequirePrivilege(SE_LOAD_DRIVER_NAME);
	if (l) {
		std::cout << "ERROR: Could not acquire SeDebugPrivilege" << std::endl;
		goto CLEANUP;
	}

	aServiceKey = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH);
	if (aServiceKey == NULL) {
		goto CLEANUP;
	}
	_snprintf_s(aServiceKey, 0x103ui64, 0x103ui64, "System\\CurrentControlSet\\Services\\%s", aService);

	l = RegOpenKeyExA(HKEY_LOCAL_MACHINE, aServiceKey, 0, KEY_READ, &hKey);
	if (l == ERROR_SUCCESS) {
		std::cout << "ERROR: The service key at " << aServiceKey << " already exists!" << std::endl;
		return -1;
	}

	l = RegCreateKeyA(HKEY_LOCAL_MACHINE, aServiceKey, &hKey); {}
	if (l) {
		std::cout << "ERROR: Could not create a registry key at " << aServiceKey << std::endl;
		goto CLEANUP;
	}

	dwData = 1;
	l = RegSetValueExA(hKey, "Type", 0, REG_DWORD, (BYTE*)&dwData, 4u);
	if (l) {
		goto CLEANUP;
	}

	l = RegSetValueExA(hKey, "ErrorControl", 0, REG_DWORD, (BYTE*)&dwData, 4u);
	if (l) {
		goto CLEANUP;
	}

	dwData = 3;
	l = RegSetValueExA(hKey, "Start", 0, REG_DWORD, (BYTE*)&dwData, 4u);
	if (l) {
		goto CLEANUP;
	}

	aDriverKey = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH);
	if (aDriverKey == NULL) {
		goto CLEANUP;
	}

	sDstPath = W2A(dstPath.c_str());
	windowsRelative = sDstPath.substr(strlen(R"(C:\Windows\)"));
	l = RegSetValueExA(hKey, "ImagePath", 0, REG_SZ, (const BYTE*)windowsRelative.c_str(), windowsRelative.size() + 1);
	if (l) {
		goto CLEANUP;
	}

	_snprintf_s(aDriverKey, MAX_PATH, MAX_PATH, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", aService);
	RtlInitAnsiString(&asDriverKey, aDriverKey);
	l = RtlAnsiStringToUnicodeString(&uDriver, &asDriverKey, TRUE);
	if (l) {
		goto CLEANUP;
	}

	ret = NtLoadDriver(&uDriver);
	if (ret) {
		std::cout << "ERROR: NtLoadDriver failed" << std::endl;
	}

CLEANUP:
	if (uDriver.Length != 0) {
		RtlFreeUnicodeString(&uDriver);
	}

	if (aServiceKey) {
		l = SHDeleteKeyA(HKEY_LOCAL_MACHINE, aServiceKey);
		if (l) {
			std::cout << "WARNING: " << "could not delete the service key at " << aServiceKey << std::endl;
		}
	}

	if (fs::is_regular_file(dstPath)) {
		try {
			fs::remove(dstPath);
		}
		catch (std::exception & e) {
			std::cout << "WARNING: " << "could not delete file at " << dstPath << std::endl;
		}
	}

	if (aDriverKey)
		HeapFree(GetProcessHeap(), NULL, aDriverKey);
	if (aServiceKey)
		HeapFree(GetProcessHeap(), NULL, aServiceKey);

	return ret;
}

int _tmain(int argc, _TCHAR* argv[])
{
	USES_CONVERSION;

	if (argc != 3) {
		std::cout << "Please provide the following arguments:" << std::endl;
		std::cout << W2A(argv[0]) << " <path to driver> <service name>" << std::endl;
		return -1;
	}


	LPSTR lpDriverImage = W2A(argv[1]);
	LPSTR lpServiceName = W2A(argv[2]);
	
	if (!fs::exists(lpDriverImage) || !fs::is_regular_file(lpDriverImage)) {
		std::cout << "ERROR: " << lpDriverImage << " does not exist or could not be read" << std::endl;
		return -1;
	}
	auto driverImagePath = fs::path(lpDriverImage);

	DWORD dwErr = LoadDriver(lpServiceName, driverImagePath);
	if (dwErr != 0) {
		std::cout << "ERROR: could not load the driver" << std::endl;
		return -1;
	} else {
		std::cout << "Driver loaded!" << std::endl;
	}

	return 0;
}

