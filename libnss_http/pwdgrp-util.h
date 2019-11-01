#define APAM_GROUP          "overlake"
#define APAM_GID            40000
#define SECONDS_BEFORE_EXP  (30*60)

struct user_entry {
    char        *name;
    uid_t       uid;
    time_t      create_time;
    char        **members;
    size_t      size;
};

struct user_entry_node {
    struct user_entry *ent;
    struct user_entry_node *next;
};

struct  user_entry* get_next_user_entry(void);
void    free_all_entries(void);
void    free_entry(struct user_entry*);
struct  user_entry* find_entry_name(const char *name);
struct  user_entry* find_entry_uid(uid_t uid);
size_t  load_all_entries(uid_t *ret_max);
