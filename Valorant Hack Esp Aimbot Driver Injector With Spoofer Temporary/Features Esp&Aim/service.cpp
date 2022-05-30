#include "service.hpp"
#include "api/xor.h"



bool service::RegisterAndStart(const std::string& driver_path)
{
	const static DWORD ServiceTypeKernel = 1;
	const std::string driver_name = std::filesystem::path(driver_path).filename().string();
	const std::string servicesPath = xorstr_("SYSTEM\\CurrentControlSet\\Services\\") + driver_name;
	const std::string nPath = xorstr_("\\??\\") + driver_path;

	HKEY dservice;
	LSTATUS status = RegCreateKeyA(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &dservice); //Returns Ok if already exists
	if (status != ERROR_SUCCESS)
	{
		printf(xorstr_("[-] Can't create service key\n"));
		return false;
	}

	status = RegSetKeyValueA(dservice, NULL, xorstr_("ImagePath"), REG_EXPAND_SZ, nPath.c_str(), (DWORD)nPath.size());
	if (status != ERROR_SUCCESS)
	{
		RegCloseKey(dservice);
		printf(xorstr_("[-] Can't create 'ImagePath' registry value\n"));
		return false;
	}

	status = RegSetKeyValueA(dservice, NULL, xorstr_("Type"), REG_DWORD, &ServiceTypeKernel, sizeof(DWORD));
	if (status != ERROR_SUCCESS)
	{
		RegCloseKey(dservice);
		printf(xorstr_("[-] Can't create 'Type' registry value\n"));
		return false;
	}

	RegCloseKey(dservice);

	HMODULE ntdll = GetModuleHandleA(xorstr_("ntdll.dll"));
	if (ntdll == NULL) {
		return false;
	}

	auto RtlAdjustPrivilege = (nt::RtlAdjustPrivilege)GetProcAddress(ntdll, xorstr_("RtlAdjustPrivilege"));
	auto NtLoadDriver = (nt::NtLoadDriver)GetProcAddress(ntdll, xorstr_("NtLoadDriver"));

	ULONG SE_LOAD_DRIVER_PRIVILEGE = 10UL;
	BOOLEAN SeLoadDriverWasEnabled;
	NTSTATUS Status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled);
	if (!NT_SUCCESS(Status))
	{
		printf(xorstr_("Fatal error: failed to acquire SE_LOAD_DRIVER_PRIVILEGE. Make sure you are running as administrator.\n"));
		return false;
	}

	std::wstring wdriver_name(driver_name.begin(), driver_name.end());
	wdriver_name = wxorstr_(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") + wdriver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_name.c_str());

	Status = NtLoadDriver(&serviceStr);
	return NT_SUCCESS(Status);
}

bool service::StopAndRemove(const std::string& driver_name)
{
	HMODULE ntdll = GetModuleHandleA(xorstr_("ntdll.dll"));
	if (ntdll == NULL)
		return false;

	std::wstring wdriver_name(driver_name.begin(), driver_name.end());
	wdriver_name = wxorstr_(L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\") + wdriver_name;
	UNICODE_STRING serviceStr;
	RtlInitUnicodeString(&serviceStr, wdriver_name.c_str());

	HKEY driver_service;
	std::string servicesPath = xorstr_("SYSTEM\\CurrentControlSet\\Services\\") + driver_name;
	LSTATUS status = RegOpenKeyA(HKEY_LOCAL_MACHINE, servicesPath.c_str(), &driver_service);
	if (status != ERROR_SUCCESS)
	{
		if (status == ERROR_FILE_NOT_FOUND) {
			return true;
		}
		return false;
	}
	RegCloseKey(driver_service);

	auto NtUnloadDriver = (nt::NtUnloadDriver)GetProcAddress(ntdll, xorstr_("NtUnloadDriver"));
	NTSTATUS st = NtUnloadDriver(&serviceStr);

	if (st != 0x0) {
		printf(xorstr_("[-] Driver Unload Failed!!\n")); Sleep(1000);
	}

	status = RegDeleteKeyA(HKEY_LOCAL_MACHINE, servicesPath.c_str());
	if (status != ERROR_SUCCESS)
	{
		return false;
	}
	return true;
}