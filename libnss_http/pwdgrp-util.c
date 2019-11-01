#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include "pwdgrp-util.h"

#define SSH_KEYS_PATH   "/var/ssh/keys"
#define AUTH_KEYS_FILE  "authorized_keys"
#define BUFFER_LENGTH   512

static struct user_entry_node *head;
static struct user_entry_node *curr;
static time_t now = 0;

void prepend_user_entry(struct user_entry *ent) {
    struct user_entry_node *node = (struct user_entry_node*) malloc (sizeof(struct user_entry_node));

    node->ent = ent;
    node->next = head->next;
    head->next = node;
    curr = head->next;
}

struct user_entry* get_next_user_entry() {
    if (curr == NULL) {
        return NULL;
    }

    struct user_entry* result = curr->ent;
    curr = curr->next;

    return result;
}

void free_all_entries(void) {
    if (head == NULL) {
        return;
    }
    struct user_entry_node *node = head->next;

    // reset head->next and curr
    head->next = NULL;
    curr = NULL;

    while (node != NULL) {
        /*
        struct user_entry *ent = node->ent;

        free(ent->name);
        free(ent);*/

        free_entry(node->ent);

        struct user_entry_node *t = node;
        node = node->next;

        free(t);
    }
}

// make sure load_all_entries() is called first
static char** get_group_members(size_t count) {
    if (count == 0) {
        return NULL;
    }

    char **result = (char**)malloc(sizeof(char*) * (count + 1));
    char **ret = result;

    struct user_entry_node *node = head->next;

    while (node != NULL) {
        if (node->ent->create_time +  SECONDS_BEFORE_EXP > now) {
            *result = strdup(node->ent->name);
            result++;
        }

        node = node->next;
    }

    *result = NULL;

    return ret;
}

struct user_entry* find_entry_uid(uid_t uid) {
    struct user_entry *result = NULL;
    free_all_entries();
    size_t count = load_all_entries(NULL);

    if (uid == APAM_GID) {
        result = (struct user_entry*)malloc(sizeof(struct user_entry));
        result->name        = strdup(APAM_GROUP);
        result->uid         = APAM_GID;
        result->create_time = 0;
        result->members     = get_group_members(count);
        result->size        = count;
    } else {
        struct user_entry_node *node = head->next;

        while (node != NULL) {
            if (node->ent->uid == uid) {
                // duplicate the found user_entry
                result = (struct user_entry*)malloc(sizeof(struct user_entry));

                result->name = strdup(node->ent->name);
                result->uid = node->ent->uid;
                result->create_time = node->ent->create_time;
                result->members = NULL;
                result->size = count;
                break;
            }

            node = node->next;
        }
    }

    free_all_entries();
    return result;
}

void free_entry(struct user_entry *ent) {
    if (ent == NULL) {
        return;
    }

    if (ent->members != NULL) {
        char** members = ent->members;

        while (*members != NULL) {
            free(*members++);
        }

        free(ent->members);
    }

    free(ent->name);
    free(ent);
}

static int is_number(const char *num) {
    while (num != NULL && !isdigit(*num++)) {
        return 0;
    }

    return 1;
}

static uid_t read_uid(const char *name) {
    char buffer[BUFFER_LENGTH];
    sprintf(buffer, "%s/%s/uid", SSH_KEYS_PATH, name);

    FILE *f = fopen(buffer, "r");

    if (f == NULL) {
        return 0;
    }

    if (fgets(buffer, BUFFER_LENGTH, f) == NULL) {
        return 0;
    }

    fclose(f);

    if(!is_number(buffer)) {
        return 0;
    }

    return atoi(buffer);
}

struct user_entry* find_entry_name(const char *name) {
    if (strcmp(APAM_GROUP, name) == 0) {
        return find_entry_uid(APAM_GID);
    }

    char auth_keys_file[BUFFER_LENGTH];
    sprintf(auth_keys_file, "%s/%s/%s", SSH_KEYS_PATH, name, AUTH_KEYS_FILE);

    struct stat statbuf;
    if (stat(auth_keys_file, &statbuf) != 0) {
        return NULL;
    }

    uid_t uid = read_uid(name);

    if (uid == 0) {
        return NULL;
    }

    // duplicate the user_entry
    struct user_entry *ret = (struct user_entry*)malloc(sizeof(struct user_entry));
    ret->name = strdup(name);
    ret->uid = uid;
    ret->create_time = statbuf.st_mtim.tv_sec;
    ret->size = 0;
    ret->members = NULL;

    return ret;
}

size_t load_all_entries(uid_t *ret_max) {
    uid_t max = 0;
    now = time(NULL);

    DIR *dir = opendir(SSH_KEYS_PATH);

    if (dir == NULL) {
        return -1;
    }
    size_t count = 0;

    if (head == NULL) {
        head = (struct user_entry_node*)malloc(sizeof(struct user_entry_node));
        head->next = NULL;
    }

    struct dirent *de;
    struct user_entry_node *c = head;

    while ((de = readdir(dir)) != NULL) {
        if (de->d_type != DT_DIR) {
            // not a directory, just ignore it
            continue;
        }

        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
            continue;
        }
        
        // expired users will be filtered out here
        struct user_entry *ent = find_entry_name(de->d_name);

        if (ent == NULL || ent->uid == 0) {
            continue;
        }

        c->next = (struct user_entry_node*)malloc(sizeof(struct user_entry_node));
        c = c->next;
        c->next = NULL;
        c->ent = ent;

        max = ent->uid > max ? ent->uid : max;

        if (ent->create_time + SECONDS_BEFORE_EXP > now) {
            ++count;
        }
    }

    closedir(dir);

    if (ret_max != NULL) {
        *ret_max = max;
    }

    // reset curr to first entry
    curr = head->next;

    return count;
}

#ifndef NDEBUG

static void print_entry(struct user_entry *e) {
    if (e == NULL) {
        printf("null entry...\n");
    } else {
        printf("name=%s uid=%d time=%ld\n", e->name, e->uid, e->create_time);
    }
}

int main(int argc, char **argv) {
while (1) {
    uid_t max = 0;
    load_all_entries(&max);

    struct group node = head->next;

    while (node != NULL) {
        struct user_entry *e = node->ent;
        print_entry(e);
        node = node->next;
    }

    printf("max uid is %d\n", max);
    free_all_entries();

    struct user_entry *ent;
    ent = find_entry_name("mike");
    print_entry(ent);
    free_entry(ent);
    ent = find_entry_name("david");
    print_entry(ent);
    free_entry(ent);
    ent = find_entry_name("wwww");
    print_entry(ent);
    free_entry(ent);

    ent = find_entry_uid(65536);
    print_entry(ent);
    free_entry(ent);
    ent = find_entry_uid(65535);
    print_entry(ent);
    free_entry(ent);
    ent = find_entry_uid(65534);
    print_entry(ent);
    free_entry(ent);
}
    return 0;
}
#endif
