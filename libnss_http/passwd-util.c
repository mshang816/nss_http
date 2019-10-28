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

static struct passwd* get_passwd(char *line) {
    struct passwd* result = malloc(sizeof(struct passwd));

    char *token;
    char *s_ptr = NULL;
    int i = 0, n = 0;

    while (1) {
        token = strtok_r(line, ":", &s_ptr); 
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

        line = NULL;
        i++;
    }

    return result;
}

static void free_all(void) {
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
}

int load_passwd(void) {
    free_all();

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
    return 0;
}

struct passwd* find_name(const char* name) {
    struct passwd_node *node = head->next;

    while (node != NULL) {
        if (!strcmp(node->pwd->pw_name, name)) {
            return node->pwd;
        }
        node = node->next;
    }

    return NULL;
}

struct passwd* find_uid(uid_t uid) {
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

static void print_all(void) {
    struct passwd_node *node = head->next;

    while (node != NULL) {
        print_passwd(node->pwd);
        node = node->next;
    }
}

static void test_find_name(const char *name) {
    struct passwd *pwd = find_name(name);
    print_passwd(pwd);
    printf("\n");
}

static void test_find_id(const uid_t id) {
    struct passwd *pwd = find_uid(id);
    print_passwd(pwd);
    printf("\n");
}
int main(int argc, char **argv) {
    while (1) {
        load_passwd();
        print_all();
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
