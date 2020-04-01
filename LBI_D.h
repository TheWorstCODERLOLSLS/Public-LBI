namespace R {
	namespace Bypass {
		void b_console(const char* t) {
			DWORD ConsoleProtect;
			VirtualProtect((PVOID)&FreeConsole, 1, PAGE_EXECUTE_READWRITE, &ConsoleProtect);
			*(BYTE*)(&FreeConsole) = 0xC3;

			AllocConsole();
			freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
			freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
			SetWindowPos(GetConsoleWindow(), HWND_TOPMOST, 0, 0, 0, 0, SWP_DRAWFRAME | SWP_NOSIZE | SWP_NOMOVE | SWP_SHOWWINDOW);
			SetConsoleTitleA(t);
		}

		DWORD ret(DWORD addr)
		{
			BYTE* tAddr = (BYTE*)addr;
			do
			{
				tAddr += 16;
			} while (!(tAddr[0] == 0x55 && tAddr[1] == 0x8B && tAddr[2] == 0xEC));

			DWORD funcSz = tAddr - (BYTE*)addr;

			PVOID nFunc = VirtualAlloc(NULL, funcSz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (nFunc == NULL)
				return addr;

			memcpy(nFunc, (void*)addr, funcSz);

			BYTE* pos = (BYTE*)nFunc;
			BOOL valid = false;
			do
			{
				if (pos[0] == 0x72 && pos[2] == 0xA1 && pos[7] == 0x8B) {
					*(BYTE*)pos = 0xEB;

					DWORD cByte = (DWORD)nFunc;
					do
					{
						if (*(BYTE*)cByte == 0xE8)
						{
							DWORD oFuncPos = addr + (cByte - (DWORD)nFunc);
							DWORD oFuncAddr = (oFuncPos + *(DWORD*)(oFuncPos + 1)) + 5;

							if (oFuncAddr % 16 == 0)
							{
								DWORD relativeAddr = oFuncAddr - cByte - 5;
								*(DWORD*)(cByte + 1) = relativeAddr;

								cByte += 4;
							}
						}

						cByte += 1;
					} while (cByte - (DWORD)nFunc < funcSz);

					valid = true;
				}
				pos += 1;
			} while ((DWORD)pos < (DWORD)nFunc + funcSz);

			if (!valid)
			{
				VirtualFree(nFunc, funcSz, MEM_RELEASE);
				return addr;
			}

			return (DWORD)nFunc;
		}
	}

	namespace Off {
		DWORD ASLR(DWORD raw) {
			return (raw - 0x400000 + (DWORD)GetModuleHandleA(0));
		}

		using t_d = int(__cdecl*)(DWORD v1, const char* v2, const char* v3, size_t v4);
		t_d deserialize_roblox = (t_d)(Bypass::ret(ASLR(0x8D4410)));

		using nt_t = int(__cdecl*)(DWORD v1);
		nt_t newthread_roblox = (nt_t)(Bypass::ret(ASLR(0x7CDE20)));

		using s_t = void(__cdecl*)(DWORD v1);
		s_t spawn_roblox = (s_t)(Bypass::ret(ASLR(0x72C2F0)));

		using ps_t = void(__cdecl*)(DWORD v1, const char* v2, int v3);
		ps_t pushlstring_roblox = (ps_t)(Bypass::ret(ASLR(0x7CE7B0)));
		
		using sf_t = void(__cdecl*)(DWORD v1, int v2, const char* v3);
		sf_t setfield_roblox = (sf_t)(Bypass::ret(ASLR(0x7CF5E0)));
	}

	namespace ASDF_Scanner {
		BOOL compare(const BYTE* location, const BYTE* aob, const char* mask) {
			for (; *mask; ++aob, ++mask, ++location) {
				__try {
					if (*mask == 'x' && *location != *aob)
						return 0;
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					return 0;
				}
			}
			return 1;
		}

		DWORD find_Pattern(DWORD size, BYTE * pattern, char* mask,
			BYTE protection = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
			SYSTEM_INFO SI = { 0 };
			GetSystemInfo(&SI);
			DWORD start = (DWORD)SI.lpMinimumApplicationAddress;
			DWORD end = (DWORD)SI.lpMaximumApplicationAddress;
			MEMORY_BASIC_INFORMATION mbi;
			while (start < end && VirtualQuery((void*)start, &mbi, sizeof(mbi))) {
				// Make sure the memory is committed, matches our protection, and isn't PAGE_GUARD.
				if ((mbi.State & MEM_COMMIT) && (mbi.Protect & protection) && !(mbi.Protect & PAGE_GUARD)) {
					// Scan all the memory in the region.
					for (DWORD i = (DWORD)mbi.BaseAddress; i < (DWORD)mbi.BaseAddress + mbi.RegionSize; ++i) {
						if (compare((BYTE*)i, pattern, mask)) {
							return i;
						}
					}
				}
				// Move onto the next region of memory.
				start += mbi.RegionSize;
			}
			return 0;
		}

		int Scan(DWORD mode, char* content, char* mask) {
			return find_Pattern(0x7FFFFFFF, (BYTE*)content, mask, mode);
		}
	}
}
