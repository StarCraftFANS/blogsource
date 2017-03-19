/*
In Visual Studio:
Project/Property/Linker/Advanced/Data Execution Prevention(DEP) -> NO

Function:
MessageBoxA(0, "4321", "4321", 0) && ExitProcess(0)
*/

#include <windows.h>
#include <stdio.h>

void popMessageBox() {
    __asm {
        jmp     start

find_function:
        push    ebp
        mov     ebp,esp

        mov     eax,fs:[0x30]           // get the pointer to PEB
        mov     eax,[eax+0x0c]          // get PEB->ldr
        mov     eax,[eax+0x14]          // get PEB->ldr.InMemoryOrderModuleList.Flink

module_loop:
        mov     eax,[eax]               // skip the 1st entry, or get the next entry
        mov     esi,[eax+0x28]          // LDR_MODULE->BaseDllName
        cmp     byte ptr [esi+0x0c],'3' // judge if the 7th char of the module is '3'
        jne     module_loop
                                        // find kernel32.dll module
        mov     eax,[eax+0x10]          // LDR_MODULE->BaseAddress

        mov     edi,eax
        add     edi,[edi+0x3c]          // IMAGE_DOS_HEADER->e_lfanew: the PE Header

        mov     edi,[edi+0x78]          // IMAGE_NT_HEADERS->OptinalHeader.DataDirectory[0].VirtualAddress
        add     edi,eax                 // the address of Export Table
        mov     ebx,edi

        mov     edi,[ebx+0x20]          // IMAGE_EXPORT_DESCRIPTOR->AddressOfNames
        add     edi,eax                 // the address of Names
        xor     ecx,ecx                 // NameOrdinals

name_loop:
        mov     esi,[edi+ecx*4]
        add     esi,eax                 // the address of Name[ecx]
        inc     ecx
        mov     edx,[esp+8]             // The first half of the parameter
        cmp     dword ptr [esi],edx
        jne     name_loop
        mov     edx,[esp+0xc]           // The second half of the parameter
        cmp     dword ptr [esi+4],edx
        jne     name_loop

        mov     edi,[ebx+0x24]          // IMAGE_EXPORT_DESCRIPTOR->AddressOfNameOrdinals
        add     edi,eax                 // the address of NameOrdinals
        mov     ecx,[edi+ecx*2]         // NameOrdinals[ecx]
        and     ecx,0xFFFF              // just use its lower 16-bits

        mov     edi,[ebx+0x1c]          // IMAGE_EXPORT_DESCRIPTOR->AddressOfFunctions
        add     edi,eax                 // the address of Functions
        dec     ecx
        sal     ecx,2
        mov     edi,[edi+ecx]           // Functions[ecx]
        add     eax,edi                 // the address of the function we need

        pop     ebp
        ret

start:
        push    0x41636f72              // "rocA"
        push    0x50746547              // "GetP"
        call    find_function           // Get GetProcAddress's address, __cdecl
        add     esp,8                   // pop "GetProcA", clear parameters we push in stack

        push    eax                     // store GetProcAddress() in stack

        push    0x7262694c              // "Libr"
        push    0x64616f4c              // "Load"
        call    find_function           // Get LoadLibraryA's address, __cdecl
        add     esp,8                   // pop "LoadLibr"

        push    eax                     // store LoadLibraryA() in stack

        push    0x3233                  // "32"
        push    0x72657375              // "user"
        push    esp                     // lpFileName="user32"
        call    eax                     // LoadLibraryA("user32.dll"), __stdcall
        add     esp,8                   // pop "user32"

        push    0x41786f                // "oxA"
        push    0x42656761              // "ageB"
        push    0x7373654d              // "Mess"
        push    esp                     // lpProcName="MessageBoxA"
        push    eax                     // hModule
        call    [esp+0x18]              // GetProcAddress(hModule,"MessageBoxA"), __stdcall
        add     esp,0xC                 // pop "MessageBoxA"
        
        xor     edi,edi
        push    edi                     // "\0"
        push    0x31323334              // "4321"
        mov     ecx,esp
        push    edi
        push    ecx
        push    ecx
        push    edi
        call    eax                     // MessagBoxA(0,"4321","4321",0), __stdcall
        add     esp,8                   // pop "4321\0"

        add     esp,8                   // pop GetProcAddress() and LoadLibrary() in stack
        
        push    0x636f7250              // "Proc"
        push    0x74697845              // "Exit"
        call    find_function           // Get ExitProcess's address, __cdecl
        add     esp,8                   // pop "ExitProc"
        
        xor     edi,edi;
        push    edi;
        call    eax;                    // ExitProcess(0)
    }
}

int main() {
    popMessageBox();
    return 0;
}