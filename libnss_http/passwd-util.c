#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define PASSWD_FILE "/home/mike/passwd"
#define LENGTH      1024

int load_passwd(void);

struct passwd_node {
    struct passwd *pwd;
    struct passwd_node *next;
};

static struct passwd_node *head = NULL;
static struct passwd_node *curr = NULL;

static struct passwd* get_passwd(const char *line) {
    struct passwd* result = malloc(sizeof(struct passwd));

    if (result == NULL) {
        return NULL;
    }

    char *s_ptr = NULL;
    char *l = (char*)line;
    int i = 0, n = 0;

    for (;;) {
        char *token = strtok_r(l, ":", &s_ptr); 

        if (token == NULL) {
            break;
        }

        switch (i) {
            case 0:
                result->pw_name = strdup(token);
                break;
            case 2:
                result->pw_uid = (uid_t)atoi(token);
                break;
            case 3:
                result->pw_gid = (gid_t)atoi(token);
                break;
            case 5:
                result->pw_dir = strdup(token);
                break;
            case 6:
                n = strlen(token);

                if (token[n - 1] == '\n') {
                    token[n - 1] = '\0';
                }
                result->pw_shell = strdup(token);
                break;
            case 1:
            case 4:
            default:
                ;
        }

        l = NULL;
        ++i;
    }

    return result;
}

void free_all_passwd(void) {
    if (head == NULL) {
        return;
    }

    struct passwd_node * node = head->next;

    while (node != NULL) {
        struct passwd *pwd = node->pwd;
        free(pwd->pw_name);
        free(pwd->pw_dir);
        free(pwd->pw_shell);
        free(pwd);

        struct passwd_node * temp = node;
        node = node->next;
        free(temp);
    }

    head->next = NULL;
    curr = NULL;
}

struct passwd* get_next_passwd(void) {
    if (curr == NULL) {
        return NULL;
    }

    struct passwd *result = curr->pwd;
    curr = curr->next;

    return result;
}


int load_passwd(void) {
    free_all_passwd();

    char line[LENGTH];
    FILE *f = fopen(PASSWD_FILE, "r");

    if (f == NULL) {
        return 1;
    }
    
    if (head == NULL) {
        head = malloc(sizeof(struct passwd_node));
        head->next = NULL;
    }

    struct passwd_node *node = head;

    while (fgets(line, LENGTH, f) != NULL) {
        struct passwd *pwd = get_passwd(line);
        node->next = malloc(sizeof(struct passwd_node));
        node = node->next;
        node->pwd = pwd;
        node->next = NULL;
    }

    fclose(f);
    // reset curr to first node
    curr = head->next;
    return 0;
}

struct passwd* find_pwd_name(const char* name) {
    load_passwd();

    struct passwd_node *node = head->next;

    while (node != NULL) {
        if (!strcmp(node->pwd->pw_name, name)) {
            return node->pwd;
        }

        node = node->next;
    }

    return NULL;
}

struct passwd* find_pwd_uid(uid_t uid) {
    load_passwd();

    struct passwd_node *node = head->next;

    while (node != NULL) {
        if (node->pwd->pw_uid == uid) {
            return node->pwd;
        }

        node = node->next;
    }

    return NULL;
}


#ifndef NDEBUG
static void print_passwd(const struct passwd *p) {
    if (p == NULL) {
        printf("Empty passwd...\n");
        return;
    }

    printf("name=%s, uid=%u, gid=%u, dir=%s, shell=%s\n", p->pw_name, p->pw_uid, p->pw_gid, p->pw_dir, p->pw_shell);
}

static void print_all_1(void) {
    struct passwd_node *node = head->next;

    while (node != NULL) {
        print_passwd(node->pwd);
        node = node->next;
    }
}

static void print_all_2(void) {
    struct passwd *pwd = NULL;

    while ((pwd = get_next_passwd()) != NULL) {
        print_passwd(pwd);
    }
}

static void test_find_name(const char *name) {
    struct passwd *pwd = find_pwd_name(name);
    print_passwd(pwd);
}

static void test_find_id(const uid_t id) {
    struct passwd *pwd = find_pwd_uid(id);
    print_passwd(pwd);
}

int main(int argc, char **argv) {
    while (1) {
        load_passwd();
        print_all_1();
        printf("\n");

        print_all_2();
        printf("\n");


        test_find_name("mike");
        test_find_name("root");
        test_find_name("xxxx");

        test_find_id(124);
        test_find_id(1000);
        test_find_id(1240);
    }

    return 0;
}
#endif
