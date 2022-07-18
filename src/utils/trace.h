#ifdef HAVE_SDT_H
#include <sys/sdt.h>
#endif


#ifdef HAVE_SDT_DTRACE_PROBE
#define __trace_cli_probe0(provider, probe) \
	DTRACE_PROBE(provider, probe)

#define __trace_cli_probe_i1(provider, probe, integer) \
	DTRACE_PROBE1(provider, probe, integer);

#define __trace_cli_probe_s1(provider, probe, filepath) ({ \
	char ____buffer[MAX_PATH]; \
	strcpy(____buffer, filepath); \
	DTRACE_PROBE1(provider, probe, ____buffer); \
})
#else
#define __trace_cli_probe0(provider, probe)
#define __trace_cli_probe_i1(provider, probe, integer)
#define __trace_cli_probe_s1(provider, probe, filepath)
#endif

