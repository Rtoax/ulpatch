#pragma once

#define INST_SYSCALL    0x0f, 0x05  /* syscall */
#define INST_INT3       0xcc        /* int3 */
#define INST_CALLQ      0xe8        /* callq */
#define INST_JMPQ       0xe9        /* jmpq */

#define JMP_TABLE_JUMP_X86_64   0x90900000000225ff /* jmp [rip+2]; nop; nop */
#define JMP_TABLE_JUMP_ARCH     JMP_TABLE_JUMP_X86_64
