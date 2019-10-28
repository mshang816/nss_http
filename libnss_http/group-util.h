#pragma once 
#include <grp.h>

int load_group(void);
struct group* get_next_group(void);
struct group* find_grp_name(const char* name); 
struct group* find_grp_gid(gid_t gid);
