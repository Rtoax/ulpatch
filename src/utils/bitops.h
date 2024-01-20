#pragma once

#include <stdint.h>

#define BIT(n)		(1UL << (n))

inline void or_32(void *addr, uint32_t val)
{
	*(uint32_t *)addr = *(uint32_t *)addr | val;
}

inline void and_32(void *addr, uint32_t val)
{
	*(uint32_t *)addr = *(uint32_t *)addr & val;
}

inline void or_64(void *addr, uint64_t val)
{
	*(uint64_t *)addr = *(uint64_t *)addr | val;
}

inline void and_64(void *addr, uint64_t val)
{
	*(uint64_t *)addr = *(uint64_t *)addr & val;
}
