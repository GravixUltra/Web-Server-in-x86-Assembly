.intel_syntax noprefix

mov rax, 41
mov rdi, 2
mov rsi, 1
mov rdx, 0
syscall

mov rbx, rax

sub rsp, 16
mov word ptr [rsp], 2
mov word ptr [rsp+2], 0x5000
mov dword ptr [rsp+4], 0
mov qword ptr [rsp+8], 0

mov rax, 49
mov rdi, rbx
mov rsi, rsp
mov rdx, 16
syscall

mov rax, 50
mov rsi, 0
syscall

server_loop:
mov rax, 43
mov rdi, rbx
xor rsi, rsi
xor rdx, rdx
syscall

mov r15, rax

mov rax, 57
syscall
cmp rax, 0
jg parent

mov rdi, rbx
mov rax, 3
syscall


sub rsp, 1024

mov r14, rsp

mov rax, 0
mov rdi, r15
mov rsi, rsp
mov rdx, 1024
syscall

mov r13, rax

cmp dword ptr [rsp], 0x54534F50
je is_post
jmp is_get

is_post:
lea rsi, [rsp+5]
mov rdi, rsi
jmp scan

is_get:
lea rsi, [rsp+4]
mov rdi, rsi

scan:
    cmp byte ptr [rdi], ' '
    je  done
    inc rdi
    jmp scan

done:
    mov byte ptr [rdi], 0

cmp dword ptr [rsp], 0x54534F50
je open_post

mov rdi, rsi
mov rax, 2
xor rsi, rsi
xor rdx, rdx
syscall
mov r12, rax
jmp cont

open_post:
mov rdi, rsi
mov rax, 2
mov rsi, 0x41
mov rdx, 0x1FF
syscall
mov r12, rax

push rax

mov rdi, r14

comp:
cmp byte ptr [rdi], 0x0D
jne next_char
cmp byte ptr [rdi+1], 0x0A
jne next_char
cmp byte ptr [rdi+2], 0x0D
jne next_char
cmp byte ptr [rdi+3], 0x0A
jne next_char
add rdi, 4
jmp found

next_char:
inc rdi
jmp comp

found:
mov rsi, rdi
mov rdx, r13
sub rdx, rdi
add rdx, r14

pop rdi
mov rax, 1
syscall

mov rax, 3
mov rdi, r12
syscall
jmp response

cont:
mov rax, 0
mov rdi, r12
mov rsi, r14
mov rdx, 1024
syscall

mov r13, rax
mov rax, 3
mov rdi, r12
syscall


response:
sub rsp, 19

mov byte ptr [rsp], 'H'
mov byte ptr [rsp+1], 'T'
mov byte ptr [rsp+2], 'T'
mov byte ptr [rsp+3], 'P'
mov byte ptr [rsp+4], '/'
mov byte ptr [rsp+5], '1'
mov byte ptr [rsp+6], '.'
mov byte ptr [rsp+7], '0'
mov byte ptr [rsp+8], ' '
mov byte ptr [rsp+9], '2'
mov byte ptr [rsp+10], '0'
mov byte ptr [rsp+11], '0'
mov byte ptr [rsp+12], ' '
mov byte ptr [rsp+13], 'O'
mov byte ptr [rsp+14], 'K'
mov byte ptr [rsp+15], 13     
mov byte ptr [rsp+16], 10     
mov byte ptr [rsp+17], 13    
mov byte ptr [rsp+18], 10 

mov rax, 1
mov rdi, r15
mov rsi, rsp
mov rdx, 19
syscall

mov rax, 1
mov rdi, r15
mov rsi, r14
mov rdx, r13
syscall

add rsp, 19
add rsp, 16
add rsp, 1024

mov rdi, r15
mov rax, 3
syscall

mov rax, 60
xor rdi, rdi
syscall

parent:
mov rdi, r15
mov rax, 3
syscall
jmp server_loop

mov rax, 60
mov rdi, 0
syscall