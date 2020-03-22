extern "C" {
#include "Lua\lua.h"
#include "Lua\lualib.h"
#include "Lua\lauxlib.h"
#include "Lua\luaconf.h"
#include "Lua\llimits.h"
}

#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include "LBI_D.h"

#include <TlHelp32.h>
#include <WinInet.h>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib, "wininet.lib")

using namespace std;

namespace Internet {
	string ReplaceAll(string subject, const string& search,
		const string& replace) {
		size_t pos = 0;
		while ((pos = subject.find(search, pos)) != string::npos) {
			subject.replace(pos, search.length(), replace);
			pos += replace.length();
		}
		return subject;
	}

	string DownloadURL(string URL) {
		HINTERNET interwebs = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, NULL);
		HINTERNET urlFile;
		string rtn;
		if (interwebs) {
			urlFile = InternetOpenUrlA(interwebs, URL.c_str(), NULL, NULL, NULL, NULL);
			if (urlFile) {
				char buffer[2000];
				DWORD bytesRead;
				do {
					InternetReadFile(urlFile, buffer, 2000, &bytesRead);
					rtn.append(buffer, bytesRead);
					memset(buffer, 0, 2000);
				} while (bytesRead);
				InternetCloseHandle(interwebs);
				InternetCloseHandle(urlFile);
				string p = ReplaceAll(rtn, "|n", "\r\n");
				return p;
			}
		}
		InternetCloseHandle(interwebs);
		string p = ReplaceAll(rtn, "|n", "\r\n");
		return p;
	}
}

int LBI() {
	R::Bypass::b_console("Public LBI | CompiledCode");

	const auto VFT = R::Off::ASLR(0x1C40458);
	const auto ScriptContext = R::ASDF_Scanner::Scan(0x04, (char*)&VFT, (char*)"xxxx"); //source note: credit asdf for scanner. is not mine i do other method.
	const auto rL = *(DWORD*)(ScriptContext + 56 * 0 + 172) - (DWORD)(ScriptContext + 56 * 0 + 172);
	*(ULONG_PTR*)(*(ULONG_PTR*)(rL + 132) + 24) = 6;
	
	lua_State* L = luaL_newstate();
	luaL_openlibs(L);

	const auto LBI_LUAU = Internet::DownloadURL("https://github.com/Compiled-Code/roblox/blob/master/lbi.luau?raw=true");
	
	while (true) {
		std::string S;
		std::getline(std::cin, S);
		
		if(S.find("https://") != std::string::npos || S.find("http://") != std::string::npos)
			S = Internet::DownloadURL(S);
		
		luaL_loadbuffer(L, S.c_str(), S.length(), "LBI");
		lua_setglobal(L, "__C__");

		luaL_dostring(L, R"(
			local bytecode = string.dump(__C__);
			__SIZE__ = #bytecode
			__BYTECODE__ = bytecode;
		)");

		lua_getglobal(L, "__BYTECODE__");
		const auto lua_bytecode = lua_tostring(L, -1);
		lua_pop(L, 1);

		lua_getglobal(L, "__SIZE__");
		const auto lua_bytecode_size = lua_tonumber(L, -1);
		lua_pop(L, 1);

		R::Off::pushlstring_roblox(rL, lua_bytecode, lua_bytecode_size);
		R::Off::setfield_roblox(rL, LUA_GLOBALSINDEX, "SCRIPT_VALUE");

		R::Off::deserialize_roblox(rL, "LBI", LBI_LUAU.c_str(), LBI_LUAU.length());
		R::Off::spawn_roblox(rL);
	}

	return 1;
}

BOOL APIENTRY DllMain(HMODULE v1, DWORD v2, void* v3)
{
	switch (v2)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(v1);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)LBI, NULL, NULL, NULL);
		break;
	case DLL_PROCESS_DETACH:
		break;
	default: break;
	}
	return TRUE;
}
