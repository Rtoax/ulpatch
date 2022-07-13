#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#include "util.h"

void daemonize(void)
{
	if (fork() != 0) exit(0); /* parent exits */
	setsid(); /* create a new session */

#if 0
	int fd;

	/* Every output goes to /dev/null. If Elfview is daemonized but
	 * the 'logfile' is set to 'stdout' in the configuration file
	 * it will not log at all.
	 */
	if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > STDERR_FILENO) close(fd);
	}
#endif
}