public shellcode_template

.code
shellcode_template:
        mov     qword ptr [rsp+8], rbx
        push    rdi
        sub     rsp, 48
        mov     rax, qword ptr gs:96
        xor     edx, edx
        mov     r9, 4711732171926431047
        mov     rcx, qword ptr [rax+24]
        mov     rax, qword ptr [rcx+32]
        mov     rcx, qword ptr [rax]
        mov     rax, qword ptr [rcx]
        mov     rdi, qword ptr [rax+32]
        movsxd  rax, dword ptr [rdi+60]
        mov     r8d, dword ptr [rax+rdi+136]
        mov     eax, dword ptr [r8+rdi+32]
        add     rax, rdi
        movsxd  rcx, dword ptr [rax]
        cmp     qword ptr [rcx+rdi], r9
        je      short _function_found
        nop
        nop

_check_next_function_name:
        movsxd  rcx, dword ptr [rax+4]
        lea     rax, qword ptr [rax+4]
        inc     edx
        cmp     qword ptr [rcx+rdi], r9
        jne     short _check_next_function_name

_function_found:
        mov     ecx, dword ptr [r8+rdi+28]
        mov     rax, 8242266044863967052
        add     rcx, rdi
        movsxd  rdx, edx
        movsxd  rbx, dword ptr [rcx+rdx*4]
        lea     rdx, qword ptr 32[rsp]
        add     rbx, rdi
        mov     qword ptr 32[rsp], rax
        mov     rcx, rdi
        mov     qword ptr 32[rsp+8], 1098478177
        call    rbx
        mov     rcx, 7218762449265455989
        mov     qword ptr 32[rsp+8], 27756
        mov     qword ptr 32[rsp], rcx
        lea     rcx, qword ptr 32[rsp]
        call    rax
        mov     rcx, 4784343847397451085
        mov     qword ptr 32[rsp+8], 4290671
        mov     qword ptr 32[rsp], rcx
        lea     rdx, qword ptr 32[rsp]
        mov     rcx, rax
        call    rbx
        mov     rcx, 7020021522101395784
        lea     r8, qword ptr 32[rsp+15]
        mov     qword ptr 32[rsp], rcx
        lea     rdx, qword ptr 32[rsp]
        mov     rcx, 9395827011843616
        xor     r9d, r9d
        mov     qword ptr 32[rsp+8], rcx
        xor     ecx, ecx
        call    rax
        mov     rax, 7165071222045767749
        mov     qword ptr 32[rsp+8], 7566181
        lea     rdx, qword ptr 32[rsp]
        mov     qword ptr 32[rsp], rax
        mov     rcx, rdi
        call    rbx
        mov     ecx, -1
        call    rax
        mov     rbx, qword ptr [rsp+64]
        add     rsp, 48
        pop     rdi
        ret     0
end
