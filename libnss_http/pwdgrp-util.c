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
    head->next = NULL;
    curr = NULL;

    while (node != NULL) {
        struct user_entry *ent = node->ent;

        free(ent->name);

        free(ent);

        struct user_entry_node *t = node;
        node = node->next;

        free(t);
    }
}

struct user_entry* find_entry_uid(uid_t uid) {
    struct user_entry *result = NULL;
    free_all_entries();
    load_all_entries(NULL);

    while (curr != NULL) {
        if (curr->ent->uid == uid) {
            // duplicate the found user_entry
            result = (struct user_entry*)malloc(sizeof(struct user_entry));
            result->name = strdup(curr->ent->name);
            result->uid = curr->ent->uid;
            result->create_time = curr->ent->create_time;
            break;
        }

        curr = curr->next;
    }
    free_all_entries();
    return result;
}

void free_entry(struct user_entry *ent) {
    if (ent == NULL) {
        return;
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

    return ret;
}

int load_all_entries(uid_t *ret_max) {
    uid_t max = 0;
    DIR *dir = opendir(SSH_KEYS_PATH);

    if (dir == NULL) {
        return 1;
    }

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
        
        struct user_entry *ent = find_entry_name(de->d_name);

        if (ent == NULL || ent->uid == 0) {
            continue;
        }

        c->next = (struct user_entry_node*)malloc(sizeof(struct user_entry_node));
        c = c->next;
        c->next = NULL;
        c->ent = ent;

        max = ent->uid > max ? ent->uid : max;
    }

    closedir(dir);

    if (ret_max != NULL) {
        *ret_max = max;
    }

    curr = head->next;

    return 0;
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
    time_t now = time(NULL);

    printf("the time now is %ld\n", now);

    uid_t max = 0;
    int ret = load_all_entries(&max);

    curr = head->next;

    while (curr != NULL) {
        struct user_entry *e = curr->ent;
        print_entry(e);
        curr = curr->next;
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
