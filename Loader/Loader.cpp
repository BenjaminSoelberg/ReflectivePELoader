#include "stdafx.h"
#include <iostream>
#include <string>

#include <Windows.h>
#include <TlHelp32.h>
#include "Loader.h"

// TODO: Handle .net ?
// TODO: What about PE32+ (64bit)
// TODO: What about TLS callbacks?
// TODO: What about calling unload
// TODO: Set correct RWX on each section and so on
// TODO: What if the base address is unavailable ?
// TODO: What about dll loading
// TODO: What if no reloc exists
// TODO: What is reloc is stripped bit was set ?
// TODO: MZ & PE values validation
// TODO: Reflective loading dll & imports?
// TODO: FileAlignment and sectionAlignment?
// TODO: Errorhandling
// TODO: How about removing part of loader data by doing the relocation prior to copying image to target
// TODO: Handle both exe and dll
// TODO: Implement calling a custom export in dll
// TODO: validate relocation type
// See : https://msdn.microsoft.com/da-dk/library/windows/desktop/ms682583(v=vs.85).aspx regarding optional dllmain
// See : https://en.wikipedia.org/wiki/Portable_Executable

// Loadlibrary template
typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
// getprocaddress template
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);

// dll entrypoint template
typedef INT(__stdcall* dllmain)(HMODULE, DWORD32, LPVOID);

// parameters for "libraryloader()" 
struct loaderdata {
    LPVOID ImageBase; //base address of dll 
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseReloc;
    PIMAGE_IMPORT_DESCRIPTOR ImportDir;

    pLoadLibraryA fnLoadLibraryA;
    pGetProcAddress fnGetProcAddress;
};


// code responsible for loading the dll in remote process:
//(this will be copied to and executed in the target process)
DWORD __stdcall LibraryLoader(LPVOID Memory)
{
    loaderdata* LoaderParams = (loaderdata*)Memory;

    PIMAGE_BASE_RELOCATION ImageRelocation = LoaderParams->BaseReloc;

    DWORD delta = (DWORD)((LPBYTE)LoaderParams->ImageBase - LoaderParams->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta
    
    while (ImageRelocation->VirtualAddress) {
        if (ImageRelocation->SizeOfBlock >= sizeof(PIMAGE_BASE_RELOCATION))
        {
            int count = (ImageRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD list = (PWORD)(ImageRelocation + 1);

            for (int i = 0; i < count; i++)
            {
                if (list[i])
                {
                    PDWORD ptr = (PDWORD)((LPBYTE)LoaderParams->ImageBase + (ImageRelocation->VirtualAddress + (list[i] & 0xFFF)));
                    *ptr += delta;
                }
            }
            ImageRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)ImageRelocation + ImageRelocation->SizeOfBlock);
        }
    }

    PIMAGE_IMPORT_DESCRIPTOR ImportDesc = LoaderParams->ImportDir;
    while (ImportDesc->Characteristics) {
        PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + ImportDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + ImportDesc->FirstThunk);
        
        HMODULE hModule = LoaderParams->fnLoadLibraryA((LPCSTR)LoaderParams->ImageBase + ImportDesc->Name);
        
        if (!hModule)
            return FALSE;
        
        while (OrigFirstThunk->u1.AddressOfData)
        {
            if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                // Import by ordinal
                DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule,
                    (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

                if (!Function)
                    return FALSE;
            
                FirstThunk->u1.Function = Function;
            }
            else
            {
                // Import by name
                PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
                DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
                if (!Function)
                    return FALSE;

                FirstThunk->u1.Function = Function;
            }
            OrigFirstThunk++;
            FirstThunk++;
        }
        ImportDesc++;
    }

	// if the dll has an entrypoint: 
    if (LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        dllmain EntryPoint = (dllmain)((LPBYTE)LoaderParams->ImageBase + LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);
        return EntryPoint((HMODULE)LoaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point 
    }
    
    return true;
}

// this is used to calculate the size of libraryloader function
DWORD WINAPI stub()
{
    return 0;
}

DWORD FindProcessId(std::wstring processName)
{
    PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processSnapshot == INVALID_HANDLE_VALUE)
		return 0;
	
	Process32First(processSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processSnapshot);
			return processInfo.th32ProcessID;
		}
	}
	CloseHandle(processSnapshot);
	return 0;
}


int main() {
	LPCWSTR DllPath = L"MyMessageBox.dll";

	HANDLE hDll = CreateFile(DllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);

	DWORD FileSize = GetFileSize(hDll, NULL);
	LPVOID FileBuffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// read the dll:
	DWORD lpNumberOfBytesRead = 0;
	ReadFile(hDll, FileBuffer, FileSize, &lpNumberOfBytesRead, NULL);

	// Target Dll's headers:
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
	PIMAGE_NT_HEADERS Ntheaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileBuffer + DosHeader->e_lfanew);

	// Open target process:
	DWORD Processld = FindProcessId(L"Loader.exe");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, Processld);

	// Allocate memory for the dll in target process: 
	LPVOID Executablelmage = VirtualAllocEx(hProcess, 0, Ntheaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	// copy headers to target process:
	WriteProcessMemory(hProcess, Executablelmage, FileBuffer, Ntheaders->OptionalHeader.SizeOfHeaders, NULL);

	PIMAGE_SECTION_HEADER SectHeader = (PIMAGE_SECTION_HEADER)(Ntheaders + 1);
	
	// copy sections of the dll to target process:
	for (int i = 0; i < Ntheaders->FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(
			hProcess,
			(PVOID)((LPBYTE)Executablelmage + SectHeader[i].VirtualAddress),
			(PVOID)((LPBYTE)FileBuffer + SectHeader[i].PointerToRawData),
			SectHeader[i].SizeOfRawData,
			NULL
		);
	}
	
	// initialize the parameters for LibraryLoader():
	loaderdata LoaderParams;
	LoaderParams.ImageBase = Executablelmage;
	LoaderParams.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)Executablelmage + DosHeader->e_lfanew);

	LoaderParams.BaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)Executablelmage +
		Ntheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	LoaderParams.ImportDir = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)Executablelmage +
		Ntheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	LoaderParams.fnLoadLibraryA = LoadLibraryA;
	LoaderParams.fnGetProcAddress = GetProcAddress;

	//TODO: Does not work with debug build as the incrmental linker creates a lot of trampoline functions hence the pointer to the 
	//TODO: function points to the trampoline and not the'actual' function. This causes the wrong code and size to be copied!
	// Allocate Memory for the loader code:
	DWORD LoaderCodeSize = (DWORD)stub - (DWORD)LibraryLoader;
	DWORD LoaderTotalSize = LoaderCodeSize + sizeof(loaderdata);
	LPVOID LoaderMemory = VirtualAllocEx(hProcess, NULL, LoaderTotalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	// Write the loader parameters to the process
	WriteProcessMemory(hProcess, LoaderMemory, &LoaderParams, sizeof(loaderdata), 0);
	
	// write the loader code to target process
	WriteProcessMemory(hProcess, (PVOID)((loaderdata*)LoaderMemory + 1), LibraryLoader, LoaderCodeSize, NULL);

	// create remote thread to execute the loader code:
//	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)((loaderdata*)LoaderMemory + 1), LoaderMemory, 0, NULL);
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((loaderdata*)LoaderMemory + 1), LoaderMemory, 0, NULL);

	std::cout << "Address of Loader: " << std::hex << LoaderMemory << std::endl;
	std::cout << "Address of Image: " << std::hex << Executablelmage << std::endl;
	std::cout << "Press any key, to exit!" << std::endl;

	// Wait for the loader to finish executing
	WaitForSingleObject(hThread, INFINITE); 
	
	std::cin.get();
	
	// free the allocated loader code
	VirtualFreeEx(hProcess, LoaderMemory, 0, MEM_RELEASE);

	return 0;
}
