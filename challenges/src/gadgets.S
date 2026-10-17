    /* gadget farm: 常见 CTF 出题手法, 提供基本 ROP gadgets */
    .text
    .globl g_pop_rdi
g_pop_rdi:
    pop %rdi
    ret
    .globl g_pop_rsi
g_pop_rsi:
    pop %rsi
    ret
    .globl g_pop_rdx
g_pop_rdx:
    pop %rdx
    ret
    .globl g_pop_rax
g_pop_rax:
    pop %rax
    ret
    .globl g_syscall
g_syscall:
    syscall
    .globl g_jmp_rsp
g_jmp_rsp:
    jmp *%rsp
    .globl g_ret
g_ret:
    ret
