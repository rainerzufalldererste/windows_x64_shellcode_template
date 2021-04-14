# Shellcode Template for Windows x64
An easily modifiable shellcode template that loads `LoadLibraryA` and `GetProcAddress` and exposes the `HMODULE` to `kernel32.dll` written in C.

There are a lot of comments in the `shellcode_template` function to better explain what's going on. If you don't want to clone the repository, here's the important part:

```c
  // Load Process Environment Block.
  PEB *pProcessEnvironmentBlock = (PEB *)__readgsqword(0x60);

  // `pProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList` contains a double linked list.
  // `Flink` and `Blink` are pointers to the next and previous element.
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
  IMAGE_NT_HEADERS *pNtHeader = (IMAGE_NT_HEADERS *)((size_t)pDosHeader + pDosHeader->e_lfanew);

  // From the NtHeader we can extract the virtual address of the export directory of this module.
  IMAGE_EXPORT_DIRECTORY *pExports = (IMAGE_EXPORT_DIRECTORY *)((size_t)pDosHeader + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

  // The exports directory contains both a list of function _names_ of this module and the associated _addresses_ of the functions.
  const int32_t *pNameOffsets = (const int32_t *)((size_t)pDosHeader + pExports->AddressOfNames);
  
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
  while (*(uint64_t *)((size_t)pDosHeader + pNameOffsets[i]) != x.text0)
    ++i;

  // We have found the index of `GetProcAddress`.

  // The entry at an index in `AddressOfNames` corresponds to an entry at the same index in `AddressOfNameOrdinals`, which resolves the index of a given name to it's corresponding entry in `AddressOfFunctions`. (DLLs can export unnamed functions, which will not be listed in `AddressOfNames`.)
  // Let's get the function name ordinal offsets and function offsets in order to retrieve the location of `GetProcAddress` in memory.
  const int16_t *pFunctionNameOrdinalOffsets = (const int16_t *)((size_t)pDosHeader + pExports->AddressOfNameOrdinals);
  const int32_t *pFunctionOffsets = (const int32_t *)((size_t)pDosHeader + pExports->AddressOfFunctions);

  // Now resolve the index in `pFunctionOffsets` from `pFunctionNameOrdinalOffsets` to get the address of the desired function in memory.
  typedef FARPROC(*GetProcAddressFunc)(HMODULE, const char *);
  GetProcAddressFunc pGetProcAddress = (GetProcAddressFunc)(const void *)((size_t)pDosHeader + pFunctionOffsets[pFunctionNameOrdinalOffsets[i]]);

  // Now that we've got `GetProcAddress`, let's use it to get `LoadLibraryA`.

  // A HMODULE is just a pointer to the base address of a module.
  HMODULE kernel32Dll = (HMODULE)pDosHeader;

  // Get `LoadLibraryA`.
  x.text0 = 0x7262694C64616F4C; // `LoadLibr`
  x.text1 = 0x0000000041797261; // `aryA\0\0\0\0`

  typedef HMODULE(*LoadLibraryAFunc)(const char *);
  LoadLibraryAFunc pLoadLibraryA = (LoadLibraryAFunc)pGetProcAddress(kernel32Dll, (const char *)&x.text0);
```

There's also an example application that demonstrates how the generated shellcode can be executed inside a child process.

### Get Started
```bash
git clone https://github.com/rainerzufalldererste/windows_x64_shellcode_template.git
cd windows_x64_shellcode_template
git submodule update --init --recursive
create_project.bat
```
Choose your compiler toolset. (VS 2015 / VS 2017)


The `shellcode_template` project includes everything to start developing custom shellcode.

### How to retrieve the shellcode?
There are many ways to retrieve the generated shellcode. 
The easiest way is probably to just step into `void shellcode_template()` in the Visual Studio Debugger and open the Disassembly View (Ctrl+Alt+D). Make sure to turn on displaying code bytes and turn off displaying source code and addresses to simplify the output.

```asm
48 89 5C 24 08       mov         qword ptr [rsp+8],rbx  
57                   push        rdi  
48 83 EC 30          sub         rsp,30h  
65 48 8B 04 25 60 00 00 00 mov         rax,qword ptr gs:[0000000000000060h]  
33 D2                xor         edx,edx  
49 B8 47 65 74 50 72 6F 63 41 mov         r8,41636F7250746547h  
48 8B 48 18          mov         rcx,qword ptr [rax+18h]  
48 8B 41 20          mov         rax,qword ptr [rcx+20h]  
48 8B 08             mov         rcx,qword ptr [rax]  
48 8B 01             mov         rax,qword ptr [rcx]  
48 8B 78 20          mov         rdi,qword ptr [rax+20h]  
48 63 47 3C          movsxd      rax,dword ptr [rdi+3Ch]  
44 8B 8C 38 88 00 00 00 mov         r9d,dword ptr [rax+rdi+0000000000000088h]  
41 8B 44 39 20       mov         eax,dword ptr [r9+rdi+20h]  
48 03 C7             add         rax,rdi  
48 63 08             movsxd      rcx,dword ptr [rax]  
4C 39 04 39          cmp         qword ptr [rcx+rdi],r8  
 ...
```

Now you can just remove the labels and disassembly and you're left with the shellcode:

```
48 89 5C 24 08
57
48 83 EC 30
65 48 8B 04 25 60 00 00 00
33 D2
49 B8 47 65 74 50 72 6F 63 41
48 8B 48 18
48 8B 41 20
48 8B 08
48 8B 01
48 8B 78 20
48 63 47 3C
44 8B 8C 38 88 00 00 00
41 8B 44 39 20
48 03 C7
48 63 08
4C 39 04 39
 ...
```

Alternatively you can just paste your code into an online compiler like [godbolt.org](https://godbolt.org/) and copy the generated MSVC assembly (that doesn't call any internal functions for i.e. buffer security cheacks or memcpy) (ie. `x64 msvc v19.latest` with `/O2 /GS-`) into an online assembler like [https://defuse.ca/online-x86-assembler.htm](https://defuse.ca/online-x86-assembler.htm). Then just copy the generated shellcode.

When using online compilers you will probably have to clean up the assembly a bit, like this:

```asm
x$ = 32
void shellcode_template(void) PROC               ; shellcode_template, COMDAT
$LN10:
        mov     QWORD PTR [rsp+8], rbx
        push    rdi
        sub     rsp, 48                             ; 00000030H
        mov     rax, QWORD PTR gs:96
        xor     edx, edx
        mov     r8, 4711732171926431047             ; 41636f7250746547H
        mov     rcx, QWORD PTR [rax+24]
        mov     rax, QWORD PTR [rcx+32]
        mov     rcx, QWORD PTR [rax]
        mov     rax, QWORD PTR [rcx]
        mov     rdi, QWORD PTR [rax+32]
        movsxd  rax, DWORD PTR [rdi+60]
        mov     r9d, DWORD PTR [rax+rdi+136]
        mov     eax, DWORD PTR [r9+rdi+32]
        add     rax, rdi
        movsxd  rcx, DWORD PTR [rax]
        cmp     QWORD PTR [rcx+rdi], r8
        je      SHORT $LN3@shellcode_
        npad    2
$LL2@shellcode_:
        movsxd  rcx, DWORD PTR [rax+4]
        lea     rax, QWORD PTR [rax+4]
        inc     edx
        cmp     QWORD PTR [rcx+rdi], r8
        jne     SHORT $LL2@shellcode_
$LN3@shellcode_:
        mov     ecx, DWORD PTR [r9+rdi+36]
        mov     rax, 8242266044863967052      ; 7262694c64616f4cH
        ...
```

can through a bit of find and replace be turned into this: (keep in mind, the defuse.ca assembler doesn't seem to like comments)

```asm
shellcode_template:
        mov     qword ptr [rsp+8], rbx
        push    rdi
        sub     rsp, 48
        mov     rax, qword ptr gs:96
        xor     edx, edx
        mov     r8, 4711732171926431047
        mov     rcx, qword ptr [rax+24]
        mov     rax, qword ptr [rcx+32]
        mov     rcx, qword ptr [rax]
        mov     rax, qword ptr [rcx]
        mov     rdi, qword ptr [rax+32]
        movsxd  rax, DWORD ptr [rdi+60]
        mov     r9d, DWORD ptr [rax+rdi+136]
        mov     eax, DWORD ptr [r9+rdi+32]
        add     rax, rdi
        movsxd  rcx, DWORD ptr [rax]
        cmp     qword ptr [rcx+rdi], r8
        je      SHORT _function_found
        
        ; `npad    2` can be turned into two `nop`s.

        nop
        nop


_find_next_function:
        movsxd  rcx, DWORD ptr [rax+4]
        lea     rax, qword ptr [rax+4]
        inc     edx
        cmp     qword ptr [rcx+rdi], r8
        jne     SHORT _find_next_function


_function_found:
        mov     ecx, DWORD ptr [r9+rdi+36]
        mov     rax, 8242266044863967052
        ...
```

### Just interested in the generated shellcode?
This is the example shellcode. It performs the following actions:
+ It finds `GetProcAddress` in `kernel32.dll`,
+ retrieves `LoadLibraryA` from `kernel32.dll`,
+ loads `user32.dll`,
+ retrieves `MessageBoxA` from `user32.dll`,
+ displays a message box,
+ retrieves `ExitProcess` from `kernel32.dll`,
+ calls `ExitProcess`.

```
  0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 
  0x00, 0x00, 0x00, 0x33, 0xD2, 0x49, 0xB8, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x41, 0x48, 
  0x8B, 0x48, 0x18, 0x48, 0x8B, 0x41, 0x20, 0x48, 0x8B, 0x08, 0x48, 0x8B, 0x01, 0x48, 0x8B, 0x78, 
  0x20, 0x48, 0x63, 0x47, 0x3C, 0x44, 0x8B, 0x8C, 0x38, 0x88, 0x00, 0x00, 0x00, 0x41, 0x8B, 0x44, 
  0x39, 0x20, 0x48, 0x03, 0xC7, 0x48, 0x63, 0x08, 0x4C, 0x39, 0x04, 0x39, 0x74, 0x12, 0x66, 0x90, 
  0x48, 0x63, 0x48, 0x04, 0x48, 0x8D, 0x40, 0x04, 0xFF, 0xC2, 0x4C, 0x39, 0x04, 0x39, 0x75, 0xF0, 
  0x41, 0x8B, 0x4C, 0x39, 0x24, 0x48, 0xB8, 0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62, 0x72, 0x48, 
  0x03, 0xCF, 0x48, 0x63, 0xD2, 0x4C, 0x0F, 0xBF, 0x04, 0x51, 0x48, 0x8D, 0x54, 0x24, 0x20, 0x41, 
  0x8B, 0x4C, 0x39, 0x1C, 0x48, 0x03, 0xCF, 0x4A, 0x63, 0x1C, 0x81, 0x48, 0x8B, 0xCF, 0x48, 0x03, 
  0xDF, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0xC7, 0x44, 0x24, 0x28, 0x61, 0x72, 0x79, 0x41, 0xFF, 
  0xD3, 0x48, 0xB9, 0x75, 0x73, 0x65, 0x72, 0x33, 0x32, 0x2E, 0x64, 0x48, 0xC7, 0x44, 0x24, 0x28, 
  0x6C, 0x6C, 0x00, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x20, 0x48, 0x8D, 0x4C, 0x24, 0x20, 0xFF, 0xD0, 
  0x48, 0xB9, 0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x48, 0xC7, 0x44, 0x24, 0x28, 0x6F, 
  0x78, 0x41, 0x00, 0x48, 0x89, 0x4C, 0x24, 0x20, 0x48, 0x8D, 0x54, 0x24, 0x20, 0x48, 0x8B, 0xC8, 
  0xFF, 0xD3, 0x48, 0xB9, 0x48, 0x61, 0x73, 0x74, 0x61, 0x20, 0x6C, 0x61, 0x4C, 0x8D, 0x44, 0x24, 
  0x2F, 0x48, 0x89, 0x4C, 0x24, 0x20, 0x48, 0x8D, 0x54, 0x24, 0x20, 0x48, 0xB9, 0x20, 0x76, 0x69, 
  0x73, 0x74, 0x61, 0x21, 0x00, 0x45, 0x33, 0xC9, 0x48, 0x89, 0x4C, 0x24, 0x28, 0x33, 0xC9, 0xFF, 
  0xD0, 0x48, 0xB8, 0x45, 0x78, 0x69, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x48, 0xC7, 0x44, 0x24, 0x28, 
  0x65, 0x73, 0x73, 0x00, 0x48, 0x8D, 0x54, 0x24, 0x20, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 
  0xCF, 0xFF, 0xD3, 0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xD0, 0x48, 0x8B, 0x5C, 0x24, 0x40, 0x48, 
  0x83, 0xC4, 0x30, 0x5F, 0xC3
```