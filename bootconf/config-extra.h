#pragma once

#include "bootconf.h"
#include <chainloader/config.h>

void dump_config (cfg_entry *config);

uint64_t set_conf_uint   (const cfg_entry *cfg, const char *name, uint64_t val);
uint64_t set_conf_string (const cfg_entry *cfg, const char *name, const char *val);
uint64_t set_conf_stamp  (const cfg_entry *cfg, const char *name, uint64_t val);
uint64_t del_conf_item   (const cfg_entry *cfg, const char *name);
size_t   write_config    (int fd, const cfg_entry *cfg);
ssize_t  snprint_item    (const char *buf, size_t space, const cfg_entry *c);

uint64_t set_conf_stamp_time(const cfg_entry *cfg, const char *name, time_t when);
uint64_t structtm_to_stamp  (const struct tm *when);

