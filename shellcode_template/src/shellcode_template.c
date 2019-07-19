#include <stdint.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#pragma warning (push, 0)
#include <winternl.h>

// This is the shellcode template function.
// Modify it to make it fit your needs.
//
// Keep in mind:
// Don't call any functions that you didn't load here (like CRT functions). If you want to split up your shellcode into multiple functions make sure to use `__declspec(forceinline)`.
__declspec(noinline) void shellcode_template()
{
  // Depending on your target you might have to 16-bit align stack pointer. Just place `and rsp, 0fffffffffffffff0h` after the initial `sub rsp XXXX` that will be generated at the start of the function.

  // Load Process Environment Block.
  PEB *pProcessEnvironmentBlock = (PEB *)__readgsqword(0x60);

  // `pProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList` contains a double linked list.
  // `Flink` and `Blink` are the pointers to the next element.
  //
  // All Windows executables should have the following module order.
  //  1. The module of the current executable.
  //  2. `ntdll.dll` (`%windir%\System32\ntdll.dll`)
  //  3. `kernel32.dll` (`%windir%\System32\kernel32.dll`)
  //
  //  ... followed by other modules.
  //
  // In order to get the `GetProcAddress` function we need to therefore get the third item (`Flink->Flink->Flink`).
  // We use the `CONTAINING_RECORD` macro to retrieve the associated table entry.
  LDR_DATA_TABLE_ENTRY *pKernel32TableEntry = CONTAINING_RECORD(pProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

  // We've ended up at the base address of `kernel32.dll`.
  IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)pKernel32TableEntry->DllBase;

  // In order to get the exported functions we need to go to the NT PE header.
  IMAGE_NT_HEADERS *pNtHeader = (IMAGE_NT_HEADERS *)((uint8_t *)pDosHeader + pDosHeader->e_lfanew);

  // From the NtHeader we can extract the virtual address of the export directory of this module.
  IMAGE_EXPORT_DIRECTORY *pExports = (IMAGE_EXPORT_DIRECTORY *)((uint8_t *)pDosHeader + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  // The exports directory contains both a list of function _names_ of this module and the associated _addresses_ of the functions.
  const int32_t *pNameOffsets = (const int32_t *)((uint8_t *)pDosHeader + pExports->AddressOfNames);
  
  // We will use this struct to store strings.
  // We are using a struct to make sure strings don't end up in another section of the executable where we wouldn't be able to address them in a different process.
  struct
  {
    uint64_t text0, text1;
  } x;

  // We're now looking for the `GetProcAddress` function. Since there's no other function starting with `GetProcA` we'll just find that instead.
  x.text0 = 0x41636F7250746547; // `GetProcA`

  int32_t i = 0;

  // We're just extracting the first 8 bytes of the strings and compare them to `GetProcA`. We'll find it eventually.
  while (*(uint64_t *)((char *)pDosHeader + pNameOffsets[i]) != x.text0)
    ++i;

  // We have found the index of `GetProcAddress`.

  // Not let's get the function offsets in order to retrieve the location of `GetProcAddress` in memory.
  const int32_t *pFunctionOffsets = (const int32_t *)((uint8_t *)pDosHeader + pExports->AddressOfFunctions);

  typedef FARPROC(*GetProcAddressFunc)(HMODULE, const char *);
  GetProcAddressFunc pGetProcAddress = (GetProcAddressFunc)(const void *)((uint8_t *)pDosHeader + pFunctionOffsets[i]);

  // Now that we've got `GetProcAddress`, let's use it to get `LoadLibraryA`.

  // A HMODULE is just a pointer to the base address of a module.
  HMODULE kernel32Dll = (HMODULE)pDosHeader;

  // Get `LoadLibraryA`.
  x.text0 = 0x7262694C64616F4C; // `LoadLibr`
  x.text1 = 0x0000000041797261; // `aryA\0\0\0\0`

  typedef HMODULE(*LoadLibraryAFunc)(const char *);
  LoadLibraryAFunc pLoadLibraryA = (LoadLibraryAFunc)pGetProcAddress(kernel32Dll, (const char *)&x.text0);

  // Load `user32.dll`.
  x.text0 = 0x642E323372657375; // `user32.d`
  x.text1 = 0x0000000000006C6C; // `ll\0\0\0\0\0\0`
  HMODULE user32Dll = pLoadLibraryA((const char *)&x.text0);

  // Get `MessageBoxA`.
  x.text0 = 0x426567617373654D; // `MessageB`
  x.text1 = 0x000000000041786F; // `oxA\0\0\0\0\0`

  typedef int32_t(*MessageBoxAFunc)(HWND, const char *, const char *, uint32_t);
  MessageBoxAFunc pMessageBoxA = (MessageBoxAFunc)pGetProcAddress(user32Dll, (const char *)&x.text0);

  // Display a message box.
  x.text0 = 0x616C206174736148; // `Hasta la`
  x.text1 = 0x0021617473697620; // ` vbista!\0`

  // MessageBoxA(NULL, "Hasta la vista", "", MB_OK);
  pMessageBoxA(NULL, (const char *)&x.text0, (const char *)&x.text1 + 7, MB_OK);

  // Load `ExitProcess` from `kernel32.dll`.
  x.text0 = 0x636F725074697845; // `ExitProc`
  x.text1 = 0x0000000000737365; // `ess\0\0\0\0\0`

  typedef void(*ExitProcessFunc)(uint32_t);
  ExitProcessFunc pExitProcess = (ExitProcessFunc)pGetProcAddress(kernel32Dll, (const char *)&x.text0);

  // Kill the current process with exit code -1.
  pExitProcess((uint32_t)-1);
}

#pragma warning (pop)

//////////////////////////////////////////////////////////////////////////

// Just a main function to call your shell code.
int main()
{
  shellcode_template();

  MessageBoxA(NULL, "Shell code has been executed.", "Success!", MB_OK); // in case your modified shell code function did not exit the current process.
}