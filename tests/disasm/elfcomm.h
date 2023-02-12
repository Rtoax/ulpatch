#include <stdint.h>
#include <assert.h>
#include <stdlib.h>

uint64_t (*byte_get) (const unsigned char *, unsigned int);

uint64_t
byte_get_little_endian (const unsigned char *field, unsigned int size)
{
  switch (size)
    {
    case 1:
      return *field;

    case 2:
      return ((uint64_t) field[0]
	      | ((uint64_t) field[1] << 8));

    case 3:
      return ((uint64_t) field[0]
	      | ((uint64_t) field[1] << 8)
	      | ((uint64_t) field[2] << 16));

    case 4:
      return ((uint64_t) field[0]
	      | ((uint64_t) field[1] << 8)
	      | ((uint64_t) field[2] << 16)
	      | ((uint64_t) field[3] << 24));

    case 5:
      return ((uint64_t) field[0]
	      | ((uint64_t) field[1] << 8)
	      | ((uint64_t) field[2] << 16)
	      | ((uint64_t) field[3] << 24)
	      | ((uint64_t) field[4] << 32));

    case 6:
      return ((uint64_t) field[0]
	      | ((uint64_t) field[1] << 8)
	      | ((uint64_t) field[2] << 16)
	      | ((uint64_t) field[3] << 24)
	      | ((uint64_t) field[4] << 32)
	      | ((uint64_t) field[5] << 40));

    case 7:
      return ((uint64_t) field[0]
	      | ((uint64_t) field[1] << 8)
	      | ((uint64_t) field[2] << 16)
	      | ((uint64_t) field[3] << 24)
	      | ((uint64_t) field[4] << 32)
	      | ((uint64_t) field[5] << 40)
	      | ((uint64_t) field[6] << 48));

    case 8:
      return ((uint64_t) field[0]
	      | ((uint64_t) field[1] << 8)
	      | ((uint64_t) field[2] << 16)
	      | ((uint64_t) field[3] << 24)
	      | ((uint64_t) field[4] << 32)
	      | ((uint64_t) field[5] << 40)
	      | ((uint64_t) field[6] << 48)
	      | ((uint64_t) field[7] << 56));

    default:
      fprintf(stderr, "Unhandled data length: %d\n", size);
      abort();
    }
}

uint64_t
byte_get_big_endian (const unsigned char *field, unsigned int size)
{
  switch (size)
    {
    case 1:
      return *field;

    case 2:
      return ((uint64_t) field[1]
	      | ((uint64_t) field[0] << 8));

    case 3:
      return ((uint64_t) field[2]
	      | ((uint64_t) field[1] << 8)
	      | ((uint64_t) field[0] << 16));

    case 4:
      return ((uint64_t) field[3]
	      | ((uint64_t) field[2] << 8)
	      | ((uint64_t) field[1] << 16)
	      | ((uint64_t) field[0] << 24));

    case 5:
      return ((uint64_t) field[4]
	      | ((uint64_t) field[3] << 8)
	      | ((uint64_t) field[2] << 16)
	      | ((uint64_t) field[1] << 24)
	      | ((uint64_t) field[0] << 32));

    case 6:
      return ((uint64_t) field[5]
	      | ((uint64_t) field[4] << 8)
	      | ((uint64_t) field[3] << 16)
	      | ((uint64_t) field[2] << 24)
	      | ((uint64_t) field[1] << 32)
	      | ((uint64_t) field[0] << 40));

    case 7:
      return ((uint64_t) field[6]
	      | ((uint64_t) field[5] << 8)
	      | ((uint64_t) field[4] << 16)
	      | ((uint64_t) field[3] << 24)
	      | ((uint64_t) field[2] << 32)
	      | ((uint64_t) field[1] << 40)
	      | ((uint64_t) field[0] << 48));

    case 8:
      return ((uint64_t) field[7]
	      | ((uint64_t) field[6] << 8)
	      | ((uint64_t) field[5] << 16)
	      | ((uint64_t) field[4] << 24)
	      | ((uint64_t) field[3] << 32)
	      | ((uint64_t) field[2] << 40)
	      | ((uint64_t) field[1] << 48)
	      | ((uint64_t) field[0] << 56));

    default:
      fprintf(stderr, "Unhandled data length: %d\n", size);
      abort();
    }
}

