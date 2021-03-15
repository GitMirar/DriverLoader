#include <optional>
#include <string>
#include <filesystem>

#include <Windows.h>
#include <winternl.h>

#include <fmt/format.h>
#include <fmt/os.h>
#include <winreg.hpp>

#pragma comment(lib, "ntdll.lib")


namespace fs = std::filesystem;


class NativeServices {
public:
	NativeServices()
	{
		const auto hNtdll = GetModuleHandleW(L"Ntdll.dll");
		if (hNtdll == 0) {
			throw std::runtime_error("Could not obtain a module handle for ntdll.dll");
		}

		_NtLoadDriver = (NT_LOAD_DRIVER_PFN)GetProcAddress(hNtdll, "NtLoadDriver");
		if (_NtLoadDriver == nullptr) {
			throw std::runtime_error("Could not obtain address of ntdll!NtLoadDriver");
		}

		_NtUnloadDriver = (NT_UNLOAD_DRIVER_PFN)GetProcAddress(hNtdll, "NtUnloadDriver");
		if (_NtUnloadDriver == nullptr) {
			throw std::runtime_error("Could not obtain address of ntdll!NtUnloadDriver");
		}
	}

	void LoadDriver(const std::wstring& DriverServiceName)
	{
		const auto		driverRegPath = std::wstring(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") + DriverServiceName;
		UNICODE_STRING	uDriverRegPath;

		RtlInitUnicodeString(&uDriverRegPath, driverRegPath.c_str());

		ThrowIfNotSuccess(_NtLoadDriver(&uDriverRegPath));
	}

	void UnloadDriver(const std::wstring& DriverServiceName)
	{
		const auto		driverRegPath = std::wstring(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") + DriverServiceName;
		UNICODE_STRING	uDriverRegPath;

		RtlInitUnicodeString(&uDriverRegPath, driverRegPath.c_str());

		ThrowIfNotSuccess(_NtUnloadDriver(&uDriverRegPath));
	}

private:

	void ThrowIfNotSuccess(NTSTATUS Status)
	{
		if (!NT_SUCCESS(Status)) {
			throw std::runtime_error(fmt::format("NT Status 0x{0:x}", (ULONG)Status));
		}
	}

	typedef NTSTATUS (*NT_LOAD_DRIVER_PFN)(_In_ PUNICODE_STRING DriverServiceName);
	typedef NTSTATUS (*NT_UNLOAD_DRIVER_PFN)(_In_ PUNICODE_STRING DriverServiceName);

	NT_LOAD_DRIVER_PFN		_NtLoadDriver;
	NT_UNLOAD_DRIVER_PFN	_NtUnloadDriver;
};


enum class Action {
	Unknown,
	LoadDriver,
	UnloadDriver
};


struct CommandLineArguments {
	Action						Action;
	std::optional<std::wstring>	ServiceName;
	std::optional<std::wstring> DriverPath;

	CommandLineArguments() : Action(Action::Unknown){}
};


class DriverLoader {
public:
	void Load(const std::wstring& ServiceName, const std::wstring& DriverPath)
	{
		CreateServiceEntry(ServiceName, DriverPath);
		_NativeServices.LoadDriver(ServiceName);
	}

	void Unload(const std::wstring& ServiceName)
	{
		_NativeServices.UnloadDriver(ServiceName);
		DeleteServiceEntry(ServiceName);
	}

private:

	void CreateServiceEntry(const std::wstring& ServiceName, const std::wstring& DriverPath)
	{
		winreg::RegKey serviceKey {
			HKEY_LOCAL_MACHINE, 
			fmt::format(L"SYSTEM\\CurrentControlSet\\Services\\{}", ServiceName),
			KEY_WRITE };

		if (ServiceName.empty()) {
			throw std::runtime_error("ServiceName is empty");
		}

		if (!fs::exists(DriverPath) || !fs::is_regular_file(DriverPath)) {
			throw std::runtime_error("The driver file is not accessible or is not a regular file");
		}

		serviceKey.SetDwordValue(L"Type", _ServiceType);
		serviceKey.SetDwordValue(L"Start", _ServiceStart);
		serviceKey.SetDwordValue(L"ErrorControl", _ServiceErrorControl);
		serviceKey.SetStringValue(L"DisplayName", ServiceName);
		serviceKey.SetExpandStringValue(L"ImagePath", std::wstring(L"\\??\\") + fs::absolute(DriverPath).wstring());
	}

	void DeleteServiceEntry(const std::wstring& ServiceName)
	{
		winreg::RegKey serviceKey{ HKEY_LOCAL_MACHINE };

		if (ServiceName.empty()) {
			throw std::runtime_error("ServiceName is empty");
		}

		serviceKey.DeleteTree(fmt::format(L"SYSTEM\\CurrentControlSet\\Services\\{}", ServiceName));
	}

	static constexpr DWORD _ServiceType = 0;
	static constexpr DWORD _ServiceStart = 0;
	static constexpr DWORD _ServiceErrorControl = 0;

	NativeServices _NativeServices;
};


CommandLineArguments	ParseCommandLineArguments(INT argc, PWSTR argv[]);
LSTATUS					RequirePrivilege(PCWSTR lpPrivilege);


int wmain(INT argc, PWSTR argv[])
try
{
	DriverLoader			driverLoader;
	CommandLineArguments	arguments{ ParseCommandLineArguments(argc, argv) };

	fmt::print(L"Obtaining the load driver priviledge...\n");

	RequirePrivilege(SE_LOAD_DRIVER_NAME);

	switch (arguments.Action)
	{
	case Action::LoadDriver:
		fmt::print(L"Loading driver {0}, service name {1}...\n", arguments.DriverPath.value(), arguments.ServiceName.value());

		driverLoader.Load(arguments.ServiceName.value(), arguments.DriverPath.value());

		break;

	case Action::UnloadDriver:
		fmt::print(L"Unloading driver of the service name {0}...\n", arguments.ServiceName.value());

		driverLoader.Unload(arguments.ServiceName.value());
		break;

	default:
		throw std::runtime_error("Unknown action requested");
	}

	return 0;
}
catch (const std::exception& e) {
	fmt::print(fmt::format("Error: {0}", e.what()));

	return -1;
}


CommandLineArguments ParseCommandLineArguments(INT argc, PWSTR argv[])
{
	CommandLineArguments arguments{};

	if (argc == 4 && std::wstring(argv[1]) == L"load") {
		arguments.DriverPath = argv[2];
		arguments.ServiceName = argv[3];
		arguments.Action = Action::LoadDriver;
	}
	else if (argc == 3 && std::wstring(argv[1]) == L"unload") {
		arguments.ServiceName = argv[2];
		arguments.Action = Action::UnloadDriver;
	}
	else {
		fmt::print(
			L"Please provide the following arguments:\n"
			L"* To load a driver  : {0} load <path to driver> <service name>\n"
			L"* To unload a driver: {0} unload <service name>\n"
			L"NOTE: the tool requires the load driver privilege.\n",
			std::wstring(argv[0]));

		throw std::runtime_error("Could not find valid arguments");
	}

	return arguments;
}


LSTATUS RequirePrivilege(PCWSTR lpPrivilege)
{
	HANDLE				hToken;
	BOOL				bErr;
	TOKEN_PRIVILEGES	tp;
	LUID				luid;

	bErr = LookupPrivilegeValueW(NULL, lpPrivilege, &luid); // lookup LUID for privilege on local system
	if (!bErr) {
		throw fmt::windows_error(GetLastError(), "Could not look up the priviledge name");
	}

	bErr = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (!bErr) {
		throw fmt::windows_error(GetLastError(), "Could not open the process token");
	}

	tp.PrivilegeCount = 1; // only adjust one privilege
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	bErr = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	CloseHandle(hToken);

	// check GetLastError() to check if privilege has been changed
	if (!bErr || GetLastError() != ERROR_SUCCESS) {
		throw fmt::windows_error(GetLastError(), "Could not look up the priviledge name");
	}

	return 0;
}
