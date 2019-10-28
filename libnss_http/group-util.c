#include <grp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define GROUP_FILE "/home/mike/group"
#define LENGTH      1024

int load_group(void);

struct group_node {
    struct group *grp;
    struct group_node *next;
};

static struct group_node *head = NULL;
static struct group_node *curr = NULL;

static struct group* get_group(const char *line) {
    struct group* result = malloc(sizeof(struct group));

    if (result == NULL) {
        return NULL;
    }

    char *s_ptr = NULL;
    char *l = (char*)line;
    int i = 0;

    for (;;) {
        char *token = strtok_r(l, ":", &s_ptr); 

        if (token == NULL) {
            break;
        }

        switch (i) {
            case 0:
                result->gr_name = strdup(token);
                break;
            case 1:
                result->gr_passwd = strdup(token);
                break;
            case 2:
                result->gr_gid = (gid_t)atoi(token);
                break;
            case 3:
                break;
            default:
                ;
        }

        l = NULL;
        ++i;
    }

    return result;
}

static void free_all(void) {
    if (head == NULL) {
        return;
    }

    struct group_node * node = head->next;

    while (node != NULL) {
        struct group *grp = node->grp;
        free(grp->gr_name);
        free(grp->gr_passwd);
        free(grp);

        struct group_node * temp = node;
        node = node->next;
        free(temp);
    }
}

struct group* get_next_group(void) {
    if (curr == NULL) {
        return NULL;
    }

    struct group *result = curr->grp;
    curr = curr->next;

    return result;
}


int load_group(void) {
    free_all();

    char line[LENGTH];
    FILE *f = fopen(GROUP_FILE, "r");

    if (f == NULL) {
        return 1;
    }
    
    if (head == NULL) {
        head = malloc(sizeof(struct group_node));
        head->next = NULL;
    }

    struct group_node *node = head;

    while (fgets(line, LENGTH, f) != NULL) {
        struct group *grp = get_group(line);
        node->next = malloc(sizeof(struct group_node));
        node = node->next;
        node->grp = grp;
        node->next = NULL;
    }

    fclose(f);
    // reset curr to first node
    curr = head->next;
    return 0;
}

struct group* find_grp_name(const char* name) {
    struct group_node *node = head->next;

    while (node != NULL) {
        if (!strcmp(node->grp->gr_name, name)) {
            return node->grp;
        }

        node = node->next;
    }

    return NULL;
}

struct group* find_grp_gid(gid_t gid) {
    struct group_node *node = head->next;

    while (node != NULL) {
        if (node->grp->gr_gid == gid) {
            return node->grp;
        }

        node = node->next;
    }

    return NULL;
}


#ifndef NDEBUG
static void print_group(const struct group *p) {
    if (p == NULL) {
        printf("Empty group...\n");
        return;
    }

    printf("name=%s, gid=%u, password=%s\n", p->gr_name, p->gr_gid, p->gr_passwd);
}

static void print_all_1(void) {
    struct group_node *node = head->next;

    while (node != NULL) {
        print_group(node->grp);
        node = node->next;
    }
}

static void print_all_2(void) {
    struct group *grp = NULL;

    while ((grp = get_next_group()) != NULL) {
        print_group(grp);
    }
}

static void test_find_name(const char *name) {
    struct group *grp = find_grp_name(name);
    print_group(grp);
}

static void test_find_id(const gid_t id) {
    struct group *grp = find_grp_gid(id);
    print_group(grp);
}
int main(int argc, char **argv) {
    while (1) {
        load_group();
        print_all_1();
        printf("\n");

        print_all_2();
        printf("\n");


        test_find_name("scanner");
        test_find_name("root");
        test_find_name("xxxx");

        test_find_id(130);
        test_find_id(46);
        test_find_id(1240);
    }

    return 0;
}
#endif
