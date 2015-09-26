[BITS 32]

start:
    mov eax, 0xDEADBEEF
    mov dx, 0x42
    out dx, eax

    hlt
    jmp $
