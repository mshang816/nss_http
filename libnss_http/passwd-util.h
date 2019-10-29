#pragma once 
#include <pwd.h>

int load_passwd(void);
struct passwd* get_next_passwd(void);
struct passwd* find_pwd_name(const char* name); 
struct passwd* find_pwd_uid(uid_t uid);
void free_all_passwd(void);
