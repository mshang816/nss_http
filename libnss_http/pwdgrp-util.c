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

#define SSH_KEYS_PATH "/etc/ssh/keys"
#define AUTH_KEYS_FILE "authorized_keys"
#define BUFFER_LENGTH 512

struct user_entry_node {
    struct user_entry *ent;
    struct user_entry_node *next;
};

struct user_entry_node *head;
struct user_entry_node *curr;

struct user_entry {
    const char  *name;
    uid_t       uid;
    time_t      create_time;
};


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

struct user_entry* read_user_entry(const char *name) {
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

    struct user_entry *ret = (struct user_entry*)malloc(sizeof(struct user_entry()));
    ret->name = strdup(name);
    ret->uid = uid;
    ret->create_time = statbuf.st_mtim.tv_sec;

    return ret;
}

static int dir_enum(uid_t *ret_max) {
    uid_t max = 0;
    DIR *dir = opendir(SSH_KEYS_PATH);

    if (dir == NULL) {
        return 1;
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
        
        struct user_entry *ent = read_user_entry(de->d_name);

        if (ent == NULL) {
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

    return 0;
}


int main(int argc, char **argv) {
    time_t now = time(NULL);

    printf("the time now is %ld\n", now);

    if (head == NULL) {
        head = (struct user_entry_node*)malloc(sizeof(struct user_entry_node));
    }

    uid_t max = 0;
    int ret = dir_enum(&max);

    curr = head->next;

    while (curr != NULL) {
        struct user_entry *e = curr->ent;

        printf("name=%s uid=%d time=%ld\n", e->name, e->uid, e->create_time);

        curr = curr->next;
    }

    printf("max uid is %d\n", max);

    return 0;
}
