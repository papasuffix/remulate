# remulate
UserMode Remote Function Emulator with PEB/TEB/TLS/STACK and Syscall Support for Windows

# Note

This has extensive but not complete syscall coverage, if for whatever reason you need more syscall coverage, find initialize_syscall_descriptors and add a line similar to this

```cpp
add_syscall("NtAllocateVirtualMemory", { handle(), inout_u64(), scalar(), inout_u64(), scalar(), scalar() });```
