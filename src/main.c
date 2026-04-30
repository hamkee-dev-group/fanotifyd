#include "config.h"
#include "daemon.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
	struct daemon_cfg cfg;
	daemon_cfg_init(&cfg);

	if (daemon_cfg_parse_argv(&cfg, argc, argv) < 0) {
		daemon_cfg_free(&cfg);
		return 2;
	}

	switch (cfg.verbose) {
	case 0:  log_set_level(LOG_LEVEL_INFO); break;
	case 1:  log_set_level(LOG_LEVEL_DEBUG); break;
	default: log_set_level(LOG_LEVEL_DEBUG); break;
	}

	int rc = daemon_run(&cfg);
	daemon_cfg_free(&cfg);
	return rc;
}
