#pragma once

/* A64 instructions are always 32 bits. */
#define BL_INSN_SIZE 4


#define INST_SYSCALL    0x01, 0x00, 0x00, 0xd4  /*0xd4000001 svc #0  = syscall*/
#define INST_INT3       0xa0, 0x00, 0x20, 0xd4  /*0xd42000a0 brk #5  = int3*/
#define INST_CALLQ      modify_me               /* callq */
#define INST_JMPQ       modify_me               /* jmpq */

#define JMP_TABLE_JUMP_AARCH64  0xd61f022058000051 /*  ldr x17 #8; br x17 */
#define JMP_TABLE_JUMP_ARCH     JMP_TABLE_JUMP_AARCH64

