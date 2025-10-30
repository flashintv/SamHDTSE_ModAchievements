#include <Windows.h>
#include "Scanner.h"

void ApplyPatches(HANDLE process, HANDLE thread)
{
	SignatureScanner scanner;
	scanner.SetProcess(process);
	scanner.GetModule("SamHD_TSE_Unrestricted.exe");
	if (scanner.TargetModule.dwBase == NULL)
	{
		std::cout << "Failed to get module information." << std::endl;
		return;
	}

	// For some reason Serious Sam HD non Fusion has a SteamAPI_RestartAppIfNecessary call
	char codeBuffer[10];
	uint32_t steamRestartApp = scanner.FindSignature(scanner.TargetModule.dwBase, scanner.TargetModule.dwSize,
		"\x52\xFF\x15\x00\x00\x00\x00\x83\xC4\x04\x84", "xxx????xxxx");
	if (steamRestartApp != NULL) {
		ReadProcessMemory(process, reinterpret_cast<void*>(steamRestartApp), &codeBuffer, sizeof(codeBuffer), NULL);

		BYTE bytes[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x30, 0xC0 }; // xor al, al

		DWORD protect;
		VirtualProtectEx(process, reinterpret_cast<void*>(steamRestartApp), _ARRAYSIZE(bytes), PAGE_EXECUTE_READWRITE, &protect);
		WriteProcessMemory(process, reinterpret_cast<void*>(steamRestartApp), bytes, _ARRAYSIZE(bytes), NULL);
		VirtualProtectEx(process, reinterpret_cast<void*>(steamRestartApp), _ARRAYSIZE(bytes), protect, &protect);
		FlushInstructionCache(process, (void*)steamRestartApp, _ARRAYSIZE(bytes));
	}
	else {
		std::cout << "Pattern for 'steamRestartApp' not found." << std::endl;
		if (thread != NULL) ResumeThread(thread);
		return;
	}
	if (thread != NULL) ResumeThread(thread);

	uint32_t checkSignature = scanner.FindSignature(scanner.TargetModule.dwBase, scanner.TargetModule.dwSize,
		"\x7D\x21\x8D\x45", "xxxx");
	if (checkSignature != NULL) {
		BYTE byte = 0xEB;

		DWORD protect;
		VirtualProtectEx(process, reinterpret_cast<void*>(checkSignature), 1, PAGE_EXECUTE_READWRITE, &protect);
		WriteProcessMemory(process, reinterpret_cast<void*>(checkSignature), &byte, 1, NULL);
		VirtualProtectEx(process, reinterpret_cast<void*>(checkSignature), 1, protect, &protect);
		FlushInstructionCache(process, (void*)checkSignature, 1);
	}
	else {
		std::cout << "Pattern for 'checkSignature' not found." << std::endl;
		return;
	}

	char* steamUserStats_func;
	uint32_t steamUserStats = scanner.FindSignature(scanner.TargetModule.dwBase, scanner.TargetModule.dwSize,
		"\xFF\x15\x00\x00\x00\x00\x85\xC0\x89\x45\xFC\x75\x1E", "xx????xxxxxxx");
	if (steamUserStats != NULL) {
		uint32_t steamUserStats_temp = NULL;
		ReadProcessMemory(process, reinterpret_cast<void*>(steamUserStats + 2), &steamUserStats_temp, sizeof(steamUserStats_temp), NULL);
		ReadProcessMemory(process, reinterpret_cast<void*>(steamUserStats_temp), &steamUserStats_func, sizeof(steamUserStats_func), NULL);
	}
	else {
		std::cout << "Pattern for 'steamUserStats' not found." << std::endl;
		return;
	}

	uint64_t set_achievement = scanner.FindSignature(scanner.TargetModule.dwBase, scanner.TargetModule.dwSize,
		"\x55\x8B\xEC\x56\x8B\xF1\xE8\x00\x00\x00\x00\x85\xC0\x75\x44", "xxxxxxx????xxxx");
	if (set_achievement != NULL) {
		BYTE movEaxBytes[] = { 0xB8 };
		BYTE bytes[] = { 0x55, 0x89, 0xE5, 0xFF, 0xD0, 0x85, 0xC0, 0x75, 0x06, 0x89, 0xEC, 0x5D, 0xC2, 0x04, 0x00, 0x8B, 0x18, 0x89, 0xC6, 0x8B, 0x55, 0x08, 0x52, 0x89, 0xC1, 0xFF, 0x53, 0x1C, 0x8B, 0x1E, 0x89, 0xF1, 0xFF, 0x53, 0x28, 0x89, 0xEC, 0x5D, 0xC2, 0x04, 0x00 };
		size_t byte_size = _ARRAYSIZE(movEaxBytes) + sizeof(void*) + _ARRAYSIZE(bytes);

		DWORD protect;
		VirtualProtectEx(process, reinterpret_cast<void*>(set_achievement), byte_size, PAGE_EXECUTE_READWRITE, &protect);

		WriteProcessMemory(process, reinterpret_cast<void*>((uintptr_t)set_achievement),
			movEaxBytes, _ARRAYSIZE(movEaxBytes), NULL);
		WriteProcessMemory(process, reinterpret_cast<void*>((uintptr_t)set_achievement + _ARRAYSIZE(movEaxBytes)),
			&steamUserStats_func, sizeof(void*), NULL);
		WriteProcessMemory(process, reinterpret_cast<void*>((uintptr_t)set_achievement + _ARRAYSIZE(movEaxBytes) + sizeof(void*)),
			bytes, _ARRAYSIZE(bytes), NULL);

		VirtualProtectEx(process, reinterpret_cast<void*>(set_achievement), byte_size, protect, &protect);
		FlushInstructionCache(process, (void*)set_achievement, byte_size);

		std::cout << "Achievement hook was successful!" << std::endl;
	}
	else {
		std::cout << "Pattern for achievement awarding function not found. The game was either updated or it's already patched!" << std::endl;
		return;
	}

	std::cout << "Patches applied successfully." << std::endl;
}