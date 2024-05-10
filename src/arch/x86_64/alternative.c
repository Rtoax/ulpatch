// SPDX-License-Identifier: GPL-2.0-only
// see linux:arch/x86/kernel/alternative.c

#include <stdlib.h>

#include <utils/compiler.h>

#include <arch/x86_64/nops.h>


#ifdef K8_NOP1
static __unused const unsigned char k8nops[] =
{
	K8_NOP1,
	K8_NOP2,
	K8_NOP3,
	K8_NOP4,
	K8_NOP5,
	K8_NOP6,
	K8_NOP7,
	K8_NOP8,
	K8_NOP5_ATOMIC
};
static __unused const unsigned char * const k8_nops[ASM_NOP_MAX+2] =
{
	NULL,
	k8nops,
	k8nops + 1,
	k8nops + 1 + 2,
	k8nops + 1 + 2 + 3,
	k8nops + 1 + 2 + 3 + 4,
	k8nops + 1 + 2 + 3 + 4 + 5,
	k8nops + 1 + 2 + 3 + 4 + 5 + 6,
	k8nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,
	k8nops + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8,
};
#endif

#ifdef P6_NOP1
static __unused const unsigned char p6nops[] =
{
	P6_NOP1,
	P6_NOP2,
	P6_NOP3,
	P6_NOP4,
	P6_NOP5,
	P6_NOP6,
	P6_NOP7,
	P6_NOP8,
	P6_NOP5_ATOMIC
};
static __unused const unsigned char * const p6_nops[ASM_NOP_MAX+2] =
{
	NULL,
	p6nops,                                 /* 0x90 */
	p6nops + 1,                             /* 0x66,0x90 */
	p6nops + 1 + 2,                         /* 0x0f,0x1f,0x00 */
	p6nops + 1 + 2 + 3,                     /* 0x0f,0x1f,0x40,0 */
	p6nops + 1 + 2 + 3 + 4,                 /* 0x0f,0x1f,0x44,0x00,0 */
	p6nops + 1 + 2 + 3 + 4 + 5,             /* 0x66,0x0f,0x1f,0x44,0x00,0 */
	p6nops + 1 + 2 + 3 + 4 + 5 + 6,         /* 0x0f,0x1f,0x80,0,0,0,0 */
	p6nops + 1 + 2 + 3 + 4 + 5 + 6 + 7,     /* 0x0f,0x1f,0x84,0x00,0,0,0,0 */
	p6nops + 1 + 2 + 3 + 4 + 5 + 6 + 7 + 8, /* 0x0f,0x1f,0x44,0x00,0 */
};
#endif


#if defined(__x86_64__)
// TODO: see linux:arch_init_ideal_nops() function
const unsigned char * const *ideal_nops = p6_nops;
#endif

