/* This doesn't require anything, just compile it as a DLL with 1 of these 3 defines enabled below for whatever
version of the game you have. I'll add 1.0.4.0 at some point. */

/* Build as Release x86! */

/* Open source because this makes certain GTA modders butt hurt */

#define COMPILE_VER_1070
//#define COMPILE_VER_1080
//#define COMPILE_VER_CE

#include <Windows.h>
#include <stdint.h>
#include <Psapi.h>
#include <fstream>
#include <iomanip>

#define BUFFER_SIZE 2048

#ifdef COMPILE_VER_1070
#define COMPILE_VER "1.0.7.0"
#endif

#ifdef COMPILE_VER_1080
#define COMPILE_VER "1.0.8.0"
#endif

#ifdef COMPILE_VER_CE
#define COMPILE_VER "Complete Edition"
#endif

#define VER_MAX 3
#define VER_MIN 0

#define MOD_NAME "CenterSteeringPatchIV.asi"
#define LOG_NAME "CenterSteeringPatchIV.log"

/* Locals for quick optimization */
volatile DWORD internalCheck1 = 0;
volatile DWORD internalCheck2 = 0;
volatile DWORD internalCheck3 = 0;
volatile DWORD vHandle1 = 0;
volatile DWORD vHandle2 = 0;
volatile DWORD vHandle3 = 0;

/* Address for game */
uint32_t gBaseAddress = 0;

HMODULE getCurrentModule()
{
	HMODULE hModule = NULL;
	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)getCurrentModule, &hModule);
	return hModule;
}

DWORD WINAPI fuckYourASILoader(HMODULE hModule)
{
	while (true)
		Sleep(1000);
	return 0;
}

void clearLog()
{
	std::ofstream ofFile(LOG_NAME, std::ofstream::out | std::ofstream::trunc);
	ofFile.close();
}

void rawLog(const std::string& szInfo, const std::string& szData)
{
	std::ofstream ofFile(LOG_NAME, std::ios_base::out | std::ios_base::app);

	if (ofFile.is_open())
	{
		SYSTEMTIME stCurrTime;
		GetLocalTime(&stCurrTime);

		ofFile << "|" <<
			std::setw(2) << std::setfill('0') << stCurrTime.wHour << ":" <<
			std::setw(2) << std::setfill('0') << stCurrTime.wMinute << ":" <<
			std::setw(2) << std::setfill('0') << stCurrTime.wSecond << "." <<
			std::setw(3) << std::setfill('0') << stCurrTime.wMilliseconds <<
			"|[" << szInfo << "] -- " << szData << "\n";

		ofFile.close();
	}
}

void writeLog(const char* szInfo, const char* szFormat, ...)
{
	char szBuf[BUFFER_SIZE];
	va_list args;
	va_start(args, szFormat);
	vsnprintf(szBuf, BUFFER_SIZE, szFormat, args);
	va_end(args);
	rawLog(std::string(szInfo), std::string(szBuf));
}

uint32_t* findPlayerPed()
{
#ifdef COMPILE_VER_1070
	return ((uint32_t * (__cdecl*)())(gBaseAddress + 0x417F40))();
#endif

#ifdef COMPILE_VER_1080
	return ((uint32_t * (__cdecl*)())(gBaseAddress + 0x3CD230))();
#endif

#ifdef COMPILE_VER_CE
	return ((uint32_t * (__cdecl*)())(gBaseAddress + 0x53F050))();
#endif
}

ULONG_PTR findPattern(const char* szPattern, const char* szMask)
{
	MODULEINFO stInfo;

	if (GetModuleInformation(GetCurrentProcess(),
		GetModuleHandle(NULL), &stInfo, sizeof(MODULEINFO)))
	{
		SIZE_T index = 0;
		ULONG_PTR startAddr = (ULONG_PTR)stInfo.lpBaseOfDll;
		for (SIZE_T i = 0; i < stInfo.SizeOfImage; i++)
		{
			if (*(PBYTE)(startAddr + i) == (BYTE)szPattern[index] ||
				szMask[index] == '?')
			{
				if (szMask[index + 1] == NULL)
					return (ULONG_PTR)((startAddr + i) - (strlen(szMask) - 1));
				index++;
			}
			else
			{
				index = 0;
			}
		}
	}
	else
		writeLog("Error", "GetModuleInformation() failed! [%d]", GetLastError());

	return 0;
}

bool patchAddress(uint32_t addr, uint32_t offset, uint32_t len)
{
	bool bRet = true;
	DWORD oldProt;
	DWORD newProt;

	if (!VirtualProtect((void*)(addr + offset), len, PAGE_EXECUTE_READWRITE, &oldProt))
	{
		writeLog("Error", "Couldn't change mem protection ENTRY");
		bRet = false;
	}

	memset((void*)(addr + offset), 0x90, len);
	
	if (!VirtualProtect((void*)(addr + offset), len, oldProt, &newProt))
	{
		writeLog("Error", "Couldn't change mem protection EXIT");
		bRet = false;
	}

	return bRet;
}

void wheelCheck1()
{
	if (vHandle1 != 0)
	{
		/* Let's skip the steering angle setter if it's our own car or nobody is in the car */
		/* 0xF66 is just checking if the car is player owned */
		if (((*(uint8_t*)(vHandle1 + 0xF66) >> 1 & 1) == 1) && (*(uint32_t*)(vHandle1 + 0xFA0) == (uint32_t)findPlayerPed() || (*(uint32_t*)(vHandle1 + 0xFA0) == 0)))
		{
			internalCheck1 = 1;
		}
		else
		{
			internalCheck1 = 0; /* Must be a ped owned car */
		}
	}
	else
	{
		internalCheck1 = 0;
	}
}

void wheelCheck2()
{
	if (vHandle2 != 0)
	{
		/* Let's skip the steering angle setter if it's our own car or nobody is in the car */
		/* 0xF66 is just checking if the car is player owned */
		if (((*(uint8_t*)(vHandle2 + 0xF66) >> 1 & 1) == 1) && (*(uint32_t*)(vHandle2 + 0xFA0) == (uint32_t)findPlayerPed() || (*(uint32_t*)(vHandle2 + 0xFA0) == 0)))
		{
			internalCheck2 = 1;
		}
		else
		{
			internalCheck2 = 0; /* Must be a ped owned car */
		}
	}
	else
	{
		internalCheck2 = 0;
	}
}

void wheelCheck3()
{
	if (vHandle3 != 0)
	{
		/* Let's skip the steering angle setter if it's our own car or nobody is in the car */
		/* 0xF16 is just checking if the car is player owned */
		if (((*(uint8_t*)(vHandle3 + 0xF16) >> 1 & 1) == 1) && (*(uint32_t*)(vHandle3 + 0xF50) == (uint32_t)findPlayerPed() || (*(uint32_t*)(vHandle3 + 0xF50) == 0)))
		{
			internalCheck3 = 1;
		}
		else
		{
			internalCheck3 = 0; /* Must be a ped owned car */
		}
	}
	else
	{
		internalCheck3 = 0;
	}
}

DWORD jumpAddr1; /* Resume back after detour */
__declspec(naked) void nakedDetour1()
{
	/* Some brain dead assembly to handle our logic swap */
	__asm
	{
		mov[vHandle1], esi /* Let's grab the car handle */
		push eax /* Store registers as the game needs them later and our wheelCheck functions will probably utilize them */
		push ebx
		push ecx
		push edx
		push esi
		call wheelCheck1 /* Take a quick detour */
		pop esi
		pop edx
		pop ecx
		pop ebx
		pop eax

		push eax
		mov eax, [internalCheck1] /* Let's check if we need to skip the wheel setter */
		cmp eax, 1
		pop eax
		je skip /* Get fucked */
		movss[esi + 0x000010D8], xmm0 /* Set wheel angle */
skip:
		jmp[jumpAddr1] /* Resume back to the game code */
	}
}

DWORD jumpAddr2; /* Resume back after detour */
__declspec(naked) void nakedDetour2()
{
	__asm
	{
		mov[vHandle2], ecx /* Let's grab the car handle */
		push eax  /* Store registers as the game needs them later and our wheelCheck functions will probably utilize them */
		push ebx
		push ecx
		push edx
		push esi
		call wheelCheck2 /* Take a quick detour */
		pop esi
		pop edx
		pop ecx
		pop ebx
		pop eax

		push eax
		mov eax, [internalCheck2] /* Let's check if we need to skip the wheel setter */
		cmp eax, 1
		pop eax
		je skip2 /* Get fucked */
		movss[ecx + 0x000010D8], xmm0 /* Set wheel angle */
skip2:
		jmp[jumpAddr2] /* Resume back to the game code */
	}
}

#ifdef COMPILE_VER_CE
DWORD jumpAddr3; /* Resume back after detour */
__declspec(naked) void nakedDetour3()
{
	__asm
	{
		mov[vHandle3], edx /* Let's grab the car handle */
		push eax  /* Store registers as the game needs them later and our wheelCheck functions will probably utilize them */
		push ebx
		push ecx
		push edx
		push esi
		call wheelCheck3 /* Take a quick detour */
		pop esi
		pop edx
		pop ecx
		pop ebx
		pop eax

		push eax
		mov eax, [internalCheck3] /* Let's check if we need to skip the wheel setter */
		cmp eax, 1
		pop eax
		je skip3 /* Get fucked */
		movss[edx + 0x00001088], xmm0 /* Set wheel angle */
skip3:
		jmp[jumpAddr3] /* Resume back to the game code */
	}
}
#endif

/* Simple detour hooking :-) */
void detourHook(void* hookAddr, void* func, int len)
{
	DWORD oldProt;
	if (!VirtualProtect(hookAddr, len, PAGE_EXECUTE_READWRITE, &oldProt))
		writeLog("Error", "Couldn't change mem protection ENTRY");

	memset(hookAddr, 0x90, len); /* Patch out */
	DWORD relativeAddr = ((DWORD)func - (DWORD)hookAddr) - 5; /* Find start of detour */
	*(BYTE*)hookAddr = 0xE9; /* Jump to our detour! */
	*(DWORD*)((DWORD)hookAddr + 1) = relativeAddr; /* Bye! */

	DWORD newProt;
	if (!VirtualProtect(hookAddr, len, oldProt, &newProt))
		writeLog("Error", "Couldn't change mem protection EXIT");
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID)
{
	if (reason == DLL_PROCESS_ATTACH)
	{
		/* Hold the line boys */
		CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)fuckYourASILoader, getCurrentModule(), 0, nullptr);

		gBaseAddress = (uint32_t)GetModuleHandle(NULL);

		clearLog();
		writeLog("Started", "[%s] v%d.%d [Game: %s]", MOD_NAME, VER_MAX, VER_MIN, COMPILE_VER);

#if defined(COMPILE_VER_1070) || defined(COMPILE_VER_1080)
		/* Let's hook into these 2 instructions because the engine handles all vehicles through these, both ped and player cars included.
			Patching them out directly makes peds unable to steer. */
		ULONG_PTR addr = findPattern("\x8B\x71\x20\xF3\x0F\x11\x81\xD8\x10\x00\x00\x8A\x54\x24\x0F", "xxxxxxxxxxxxxxx");
		if (addr != 0)
		{
			writeLog("Info", "Found engine-on exit address! Hooking...");
			jumpAddr2 = addr + 8 + 3; /* Move forward to the correct return location */
			detourHook((void*)(addr + 3), nakedDetour2, 8); /* Detour time! */
			writeLog("Info", "Success!");
		}
		else
		{
			writeLog("Error", "Couldn't find address!");
		}

		addr = findPattern("\x8B\xCE\xF3\x0F\x11\x86\xD8\x10\x00\x00\xF3\x0F\x11\x86\xC8\x10\x00\x00", "xxxxxxxxxxxxxxxxxx");
		if (addr != 0)
		{
			writeLog("Info", "Found frame steer address! Hooking...");
			jumpAddr1 = addr + 2 + 8; /* Move forward to the correct return location */
			detourHook((void*)(addr + 2), nakedDetour1, 8); /* Detour time! */
			writeLog("Info", "Success!");
		}
		else
		{
			writeLog("Error", "Couldn't find address!");
		}

		/* We don't need these two next instructions so patch them out, they only affect player driven cars */
		addr = findPattern("\x8B\xE5\x5D\xC3\x0F\x57\xC0\x80\xA6\x00\x00\x00\x00\x7F\xF3\x0F\x11\x86\xD8\x10\x00\x00\xF3\x0F\x11\x86\xC8\x10\x00\x00", "xxxxxxxxx????xxxxxxxxxxxxxxxxx");
		if (addr != 0)
		{
			writeLog("Info", "Found engine-off exit address 1! Patching...");
			if (patchAddress(addr, 14, 8))
			{
				writeLog("Info", "Success!");
			}
		}
		else
		{
			writeLog("Error", "Couldn't find address!");
		}

		/* Snip snip */
		addr = findPattern("\x5E\xC3\x0F\x57\xC0\x80\xA6\x00\x00\x00\x00\x7F\xF3\x0F\x11\x86\xD8\x10\x00\x00\xF3\x0F\x11\x86\xC8\x10\x00\x00", "xxxxxxx????xxxxxxxxxxxxxxxxx");
		if (addr != 0)
		{
			writeLog("Info", "Found engine-off exit address 2! Patching...");
			if (patchAddress(addr, 12, 8))
			{
				writeLog("Info", "Success!");
			}
		}
		else
		{
			writeLog("Error", "Couldn't find address!");
		}

		/* Bikes 1 */
		addr = findPattern("\x50\x8B\xCE\xF3\x0F\x11\x86\xCC\x10\x00\x00\xF3\x0F\x11\x86\xD8\x10\x00\x00", "xxxxxxxxxxxxxxxxxxx");
		if (addr != 0)
		{
			writeLog("Info", "Found engine-off exit bike address 1! Patching...");
			if (patchAddress(addr, 11, 8))
			{
				writeLog("Info", "Success!");
			}
		}
		else
		{
			writeLog("Error", "Couldn't find address!");
		}

		/* Bikes 2 */
		addr = findPattern("\x76\x03\x0F\x28\xC2\xF3\x0F\x59\x05\x00\x00\x00\x00\xF3\x0F\x11\x86\xD8\x10\x00\x00", "xxxxxxxxx????xxxxxxxx");
		if (addr != 0)
		{
			writeLog("Info", "Found engine-off exit bike address 2! Patching...");
			if (patchAddress(addr, 13, 8))
			{
				writeLog("Info", "Success!");
			}
		}
		else
		{
			writeLog("Error", "Couldn't find address!");
		}

		/* Bikes 3 (some weird useless code that sets bike steering to 0 for like 1 frame, thanks Rockstar */
		addr = findPattern("\xEB\x13\x0F\x57\xC0\xF3\x0F\x11\x86\xD8\x10\x00\x00\xF3\x0F\x11\x86\x54\x14\x00\x00", "xxxxxxxxxxxxxxxxxxxxx");
		if (addr != 0)
		{
			writeLog("Info", "Found entry bike address! Patching...");
			if (patchAddress(addr, 5, 8))
			{
				writeLog("Info", "Success!");
			}
		}
		else
		{
			writeLog("Error", "Couldn't find address!");
		}
#endif

#ifdef COMPILE_VER_CE
		/* CE patching, for some retarded reason the logic changed heavily and now only needs 2 instructions NOPed and 1 hooked */
		ULONG_PTR addr = findPattern("\x8B\xCE\xC7\x86\x88\x10\x00\x00\x00\x00\x00\x00\xC7\x86\x78\x10\x00\x00\x00\x00\x00\x00\xE8\x68\x50\x89\xFF\x84\xC0\x75\x0A", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
		if (addr != 0)
		{
			writeLog("Info", "Found exit address 1! Patching...");
			if (patchAddress(addr, 2, 10))
			{
				writeLog("Info", "Success!");
			}
		}
		else
		{
			writeLog("Error", "Couldn't find address!");
		}

		/* Thanks Rockstar */
		addr = findPattern("\x8B\xE5\x5D\xC3\x80\xA1\x00\x00\x00\x00\x7F\xC7\x81\x88\x10\x00\x00\x00\x00\x00\x00\xC7\x81\x78\x10\x00\x00\x00\x00\x00\x00", "xxxxxx????xxxxxxxxxxxxxxxxxxxxx");
		if (addr != 0)
		{
			writeLog("Info", "Found exit address 2! Patching...");
			if (patchAddress(addr, 11, 10))
			{
				writeLog("Info", "Success!");
			}
		}
		else
		{
			writeLog("Error", "Couldn't find address!");
		}

		/* Bikes 1 */
		addr = findPattern("\x51\x8B\xCE\xC7\x86\x7C\x10\x00\x00\x00\x00\x00\x00\xC7\x86\x88\x10\x00\x00\x00\x00\x00\x00", "xxxxxxxxxxxxxxxxxxxxxxx");
		if (addr != 0)
		{
			writeLog("Info", "Found exit bike address 1! Patching...");
			if (patchAddress(addr, 13, 10))
			{
				writeLog("Info", "Success!");
			}
		}
		else
		{
			writeLog("Error", "Couldn't find address!");
		}

		/* Bikes 2 */
		addr = findPattern("\x0F\x28\xC1\xF3\x0F\x59\x05\x00\x00\x00\x00\xF3\x0F\x11\x86\x88\x10\x00\x00\x24\x7F\xC7\x86", "xxxxxxx????xxxxxxxxxxxx");
		if (addr != 0)
		{
			writeLog("Info", "Found exit bike address 2! Patching...");
			if (patchAddress(addr, 11, 8))
			{
				writeLog("Info", "Success!");
			}
		}
		else
		{
			writeLog("Error", "Couldn't find address!");
		}

		/* Bikes 3 (1 frame reset) */
		addr = findPattern("\x74\x1B\xE8\x00\x00\x00\x00\xEB\x14\xC7\x86\x88\x10\x00\x00\x00\x00\x00\x00\xC7\x86\x04\x14", "xxx????xxxxxxxxxxxxxxxx");
		if (addr != 0)
		{
			writeLog("Info", "Found entry bike address! Patching...");
			if (patchAddress(addr, 9, 10))
			{
				writeLog("Info", "Success!");
			}
		}
		else
		{
			writeLog("Error", "Couldn't find address!");
		}

		/* Hook that bastard up */
		addr = findPattern("\x8B\x72\x20\xF3\x0F\x11\x82\x88\x10\x00\x00\x8A\x44\x24\x0B\x80\xE1\x7F\xC0\xE0\x07", "xxxxxxxxxxxxxxxxxxxxx");
		if (addr != 0)
		{
			writeLog("Info", "Found frame steer address! Hooking...");
			jumpAddr3 = addr + 3 + 8; /* Move forward to the correct return location */
			detourHook((void*)(addr + 3), nakedDetour3, 8); /* Detour time! */
			writeLog("Info", "Success!");
		}
		else
		{
			writeLog("Error", "Couldn't find address!");
		}
#endif

		writeLog("Finished", "Patching complete.");
	}
	return TRUE;
}