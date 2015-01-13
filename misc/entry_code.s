[BITS 16]
size equ (64<<10)

start:
    mov dx, 0xDEAD
    in  eax, dx
    out dx, eax

    hlt
    jmp $


times (0xFFF0 - ($ - start)) db 0 

reset_vector:
    jmp     start
    db 0
    db 0
    db 0
    db 0
    db 0
    db 0
    db 0
    db 0
    db 0
    db 0
    db 0
    db 0
    db 0

