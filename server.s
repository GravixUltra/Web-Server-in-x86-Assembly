.intel_syntax noprefix

; =========================
; socket(AF_INET, SOCK_STREAM, 0)
; syscall: rax=41
; args: rdi=domain, rsi=type, rdx=protocol
; returns: fd in rax
; =========================
mov rax, 41              ; __NR_socket
mov rdi, 2               ; AF_INET
mov rsi, 1               ; SOCK_STREAM
mov rdx, 0               ; protocol = 0 (IP)
syscall

mov rbx, rax             ; save listening socket fd in rbx


; =========================
; Build sockaddr_in on stack (16 bytes)
; struct sockaddr_in {
;   sa_family_t    sin_family;   (2 bytes)
;   in_port_t      sin_port;     (2 bytes, network byte order!)
;   struct in_addr sin_addr;     (4 bytes)
;   unsigned char  sin_zero[8];  (8 bytes)
; }
; =========================
sub rsp, 16
mov word ptr [rsp], 2         ; sin_family = AF_INET

; NOTE: network byte order (big-endian). You store 0x5000 so in memory
; it becomes bytes 00 50 -> port 80.
mov word ptr [rsp+2], 0x5000  ; sin_port = htons(80) effectively

mov dword ptr [rsp+4], 0      ; sin_addr = INADDR_ANY (0.0.0.0)
mov qword ptr [rsp+8], 0      ; sin_zero padding = 0


; =========================
; bind(listen_fd, &addr, 16)
; syscall: rax=49
; args: rdi=sockfd, rsi=addr*, rdx=addrlen
; =========================
mov rax, 49              ; __NR_bind
mov rdi, rbx             ; sockfd
mov rsi, rsp             ; sockaddr_in*
mov rdx, 16              ; sizeof(sockaddr_in)
syscall


; =========================
; listen(listen_fd, backlog)
; syscall: rax=50
; args: rdi=sockfd, rsi=backlog
; =========================
mov rax, 50              ; __NR_listen
mov rsi, 0               ; backlog=0 (works but tiny; usually >0)
syscall


; =========================
; Main accept loop
; =========================
server_loop:
mov rax, 43              ; __NR_accept
mov rdi, rbx             ; listening socket fd
xor rsi, rsi             ; addr = NULL
xor rdx, rdx             ; addrlen = NULL
syscall

mov r15, rax             ; r15 = client socket fd (accepted)


; =========================
; fork()
; syscall: rax=57
; returns:
;   parent: rax = child's pid (>0)
;   child : rax = 0
; =========================
mov rax, 57              ; __NR_fork
syscall
cmp rax, 0
jg parent                ; if rax > 0 => parent path


; =========================
; CHILD PROCESS
; Close listening socket in child (not needed in child)
; close(listen_fd)
; syscall: rax=3, rdi=fd
; =========================
mov rdi, rbx
mov rax, 3               ; __NR_close
syscall


; =========================
; Allocate request buffer on stack (1024 bytes)
; r14 will hold buffer base
; =========================
sub rsp, 1024
mov r14, rsp             ; r14 = request buffer base


; =========================
; read(client_fd, buf, 1024)
; syscall: rax=0
; args: rdi=fd, rsi=buf, rdx=count
; returns: bytes read in rax
; =========================
mov rax, 0               ; __NR_read
mov rdi, r15             ; client fd
mov rsi, rsp             ; buffer
mov rdx, 1024
syscall

mov r13, rax             ; r13 = request length read


; =========================
; Decide GET vs POST by checking first 4 bytes
; You compare against 0x54534F50 which is "POST" in little-endian:
; bytes: 50 4F 53 54 => 'P''O''S''T'
; =========================
cmp dword ptr [rsp], 0x54534F50
je is_post
jmp is_get


; =========================
; Parse requested path
; For "POST /path HTTP/1.1", path begins at buffer+5 (after "POST ")
; For "GET /path HTTP/1.1",  path begins at buffer+4 (after "GET ")
; You then scan until the next space and null-terminate it.
; =========================
is_post:
lea rsi, [rsp+5]         ; rsi = pointer to path
mov rdi, rsi             ; rdi = scanning pointer
jmp scan

is_get:
lea rsi, [rsp+4]         ; rsi = pointer to path
mov rdi, rsi

scan:
    cmp byte ptr [rdi], ' '  ; find space after path
    je  done
    inc rdi
    jmp scan

done:
    mov byte ptr [rdi], 0    ; replace space with NUL terminator => C-string path


; =========================
; If POST, open file with O_CREAT|O_WRONLY (and mode 0777)
; Otherwise open read-only.
; =========================
cmp dword ptr [rsp], 0x54534F50
je open_post

; ---- GET: open(path, O_RDONLY, 0)
mov rdi, rsi             ; filename = path
mov rax, 2               ; __NR_open
xor rsi, rsi             ; flags = 0 (O_RDONLY)
xor rdx, rdx             ; mode not used
syscall
mov r12, rax             ; r12 = file fd
jmp cont


; ---- POST: open(path, O_WRONLY|O_CREAT, 0777)
open_post:
mov rdi, rsi             ; filename = path
mov rax, 2               ; __NR_open
mov rsi, 0x41            ; flags = 0x1|0x40 => O_WRONLY|O_CREAT
mov rdx, 0x1FF           ; mode = 0777
syscall
mov r12, rax             ; r12 = file fd

; Save returned fd on stack so we can use it later for write()
push rax


; =========================
; Find start of POST body by searching for "\r\n\r\n"
; r14 = base of request buffer
; rdi = scanning pointer
; =========================
mov rdi, r14

comp:
cmp byte ptr [rdi], 0x0D       ; '\r'
jne next_char
cmp byte ptr [rdi+1], 0x0A     ; '\n'
jne next_char
cmp byte ptr [rdi+2], 0x0D     ; '\r'
jne next_char
cmp byte ptr [rdi+3], 0x0A     ; '\n'
jne next_char
add rdi, 4                     ; rdi now points to start of body
jmp found

next_char:
inc rdi
jmp comp


; =========================
; Write body to file:
; - rsi = pointer to body
; - rdx = number of bytes in body
;   computed as: total_read - (body_ptr - base)
; =========================
found:
mov rsi, rdi                   ; buffer = body start

mov rdx, r13                   ; rdx = total request bytes read
sub rdx, rdi                   ; rdx = total - body_ptr
add rdx, r14                   ; rdx = total - (body_ptr - base)

; restore file fd into rdi
pop rdi

mov rax, 1                     ; __NR_write
syscall

; close(file_fd)  (NOTE: you currently close r12 later too; in POST path you
; close via r12 afterwards - just be aware of double-close possibility.)
mov rax, 3                     ; __NR_close
mov rdi, r12
syscall

jmp response


; =========================
; GET: read file into same request buffer (r14)
; Then close file.
; =========================
cont:
mov rax, 0                     ; __NR_read
mov rdi, r12                   ; file fd
mov rsi, r14                   ; buffer (reuse stack buffer)
mov rdx, 1024
syscall

mov r13, rax                   ; r13 = bytes read from file

mov rax, 3                     ; __NR_close
mov rdi, r12
syscall


; =========================
; HTTP response:
; You build "HTTP/1.0 200 OK\r\n\r\n" on stack and send it,
; then send r14 buffer content (file data for GET, or original request for POST
; depending on what you left in r14/r13).
; =========================
response:
sub rsp, 19

; Write the literal header bytes (19 bytes total)
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
mov byte ptr [rsp+15], 13      ; '\r'
mov byte ptr [rsp+16], 10      ; '\n'
mov byte ptr [rsp+17], 13      ; '\r'
mov byte ptr [rsp+18], 10      ; '\n'

; write(client_fd, header, 19)
mov rax, 1                     ; __NR_write
mov rdi, r15                   ; client fd
mov rsi, rsp                   ; header
mov rdx, 19
syscall

; write(client_fd, body, r13)
; For GET: r14 has file contents, r13 is file size read
; For POST: r14 still has request buffer, r13 is original request size
; (but you jump to response after writing the POST body to file without
; updating r13 to body length, so this echoes the request bytes read)
mov rax, 1                     ; __NR_write
mov rdi, r15
mov rsi, r14
mov rdx, r13
syscall


; =========================
; Stack cleanup:
; - header (19)
; - sockaddr_in (16)
; - request buffer (1024)
; =========================
add rsp, 19
add rsp, 16
add rsp, 1024

; close(client_fd)
mov rdi, r15
mov rax, 3                     ; __NR_close
syscall

; exit(0) in child
mov rax, 60                    ; __NR_exit
xor rdi, rdi
syscall


; =========================
; PARENT PROCESS:
; Close accepted client socket and loop back to accept again.
; Parent keeps listening socket open.
; =========================
parent:
mov rdi, r15
mov rax, 3                     ; __NR_close
syscall
jmp server_loop


; Unreachable in normal flow (server_loop never ends),
; but this is an exit(0) sequence:
mov rax, 60
mov rdi, 0
syscall
