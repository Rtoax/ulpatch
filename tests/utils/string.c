#include <sys/types.h>
#include <unistd.h>

#include <utils/log.h>
#include <utils/list.h>

#include "../test_api.h"


TEST(Utils,	memshow,	0)
{
#define TEST_DATA	"Hello World"
	memshow(TEST_DATA, sizeof(TEST_DATA));

	return 0;
}

