#ifndef FAN_POLICY_H
#define FAN_POLICY_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "output.h"














struct policy_cfg {
	char         **canaries;         
	size_t         n_canaries;

	uint32_t       burst_threshold;  
	uint32_t       burst_window_ms;

	char          *hook_cmd;         
	uint32_t       hook_cooldown_ms; 
	int            deny_on_alert;    
};

struct policy_state;

struct policy_state *policy_new(const struct policy_cfg *cfg, struct out_sink *out);
void                 policy_free(struct policy_state *p);

 
struct policy_input {
	uint64_t    ts_ms;
	uint64_t    mask;
	pid_t       pid;
	const char *comm;
	const char *exe;
	const char *path;
};

uint32_t policy_on_event(struct policy_state *p, const struct policy_input *in);

 
void policy_tick(struct policy_state *p, uint64_t now_ms);

 
size_t policy_window_count(const struct policy_state *p);

#endif
