// https://github.com/Zer0Mem0ry/SignatureScanner
#pragma once

#include <iostream>
#include <string>

#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>


// Better than using namespace std;

using std::cout;
using std::endl;
using std::string;

// datatype for a module in memory (dll, regular exe) 
struct module
{
	uint32_t dwBase = NULL;
	uint32_t dwSize = NULL;
};

class SignatureScanner
{
public:
	module TargetModule;  // Hold target module
	HANDLE TargetProcess; // for target process
	DWORD  TargetId;      // for target process

	void SetProcess(HANDLE process) {
		TargetProcess = process;
		TargetId = GetProcessId(process);
	}

	// For getting a handle to a process
	HANDLE GetProcess(const char* processName)
	{
		HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		PROCESSENTRY32 entry;
		entry.dwSize = sizeof(entry);

		do
			if (!strcmp(entry.szExeFile, processName)) {
				TargetId = entry.th32ProcessID;
				CloseHandle(handle);
				TargetProcess = OpenProcess(PROCESS_ALL_ACCESS, false, TargetId);
				return TargetProcess;
			}
		while (Process32Next(handle, &entry));

		return nullptr;
	}

	module GetModuleWithEnum(const char* moduleName) {
		DWORD needed_bytes;
		if (!EnumProcessModules(TargetProcess, NULL, 0, &needed_bytes)) {
			printf("EnumProcessModules failed: %u\n", GetLastError());
			return { };
		}

		HMODULE* modules = new HMODULE[needed_bytes / sizeof(HMODULE)];
		EnumProcessModules(TargetProcess, modules, needed_bytes, &needed_bytes);

		MODULEINFO modInfo;
		char modName[MAX_PATH];
		for (unsigned int i = 0; i < (needed_bytes / sizeof(HMODULE)); i++) {
			GetModuleBaseName(TargetProcess, modules[i], modName, MAX_PATH);
			if (!strcmp(modName, moduleName)) {
				GetModuleInformation(TargetProcess, modules[i], &modInfo, sizeof(MODULEINFO));
				delete[] modules;

				TargetModule = { (uint32_t)modInfo.lpBaseOfDll, (uint32_t)modInfo.SizeOfImage };
				return TargetModule;
			}
		}
	}

	// For getting information about the executing module
	module GetModule(const char* moduleName) {
		HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, TargetId);
		MODULEENTRY32 mEntry;
		mEntry.dwSize = sizeof(mEntry);

		do {
			if (!strcmp(mEntry.szModule, (LPSTR)moduleName)) {
				CloseHandle(hmodule);

				TargetModule = { (uint32_t)mEntry.hModule, mEntry.modBaseSize };
				return TargetModule;
			}
		} while (Module32Next(hmodule, &mEntry));

		module mod = { (DWORD)false, (DWORD)false };
		return mod;
	}

	// Basic WPM wrapper, easier to use.
	template <typename var>
	bool WriteMemory(uint32_t Address, var Value) {
		return WriteProcessMemory(TargetProcess, (LPVOID)Address, &Value, sizeof(var), 0);
	}

	// Basic RPM wrapper, easier to use.
	template <typename var>
	var ReadMemory(uint32_t Address) {
		var value;
		ReadProcessMemory(TargetProcess, (LPCVOID)Address, &value, sizeof(var), NULL);
		return value;
	}

	// for comparing a region in memory, needed in finding a signature
	bool MemoryCompare(const BYTE* bData, const BYTE* bMask, const char* szMask) {
		for (; *szMask; ++szMask, ++bData, ++bMask) {
			if (*szMask == 'x' && *bData != *bMask) {
				return false;
			}
		}
		return (*szMask == NULL);
	}

	// for finding a signature/pattern in memory of another process
	uint32_t FindSignature(uint32_t start, uint32_t size, const char* sig, const char* mask)
	{
		BYTE* data = new BYTE[size];
		SIZE_T bytesRead;

		ReadProcessMemory(TargetProcess, (LPVOID)start, data, size, &bytesRead);

		for (uint32_t i = 0; i < size; i++)
		{
			if (MemoryCompare((const BYTE*)(data + i), (const BYTE*)sig, mask)) {
				delete[] data;
				return start + i;
			}
		}
		delete[] data;
		return NULL;
	}
};