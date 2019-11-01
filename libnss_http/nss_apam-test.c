#include <stdio.h>
#include "nss_apam.h"

/// passwd
enum nss_status _nss_apam_setpwent(int stayopen);
enum nss_status _nss_apam_endpwent(void);
enum nss_status _nss_apam_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop);
enum nss_status _nss_apam_getpwuid_r(uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop);
enum nss_status _nss_apam_getpwnam_r(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop);

// group
enum nss_status _nss_apam_setgrent(int stayopen);
enum nss_status _nss_apam_endgrent(void);
enum nss_status _nss_apam_getgrent_r(struct group *result, char *buffer, size_t buflen, int *errnop);
enum nss_status _nss_apam_getgrgid_r(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop);
enum nss_status _nss_apam_getgrnam_r(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop);

#define BUFFER_LEN  1024

void print_grp(enum nss_status ret, struct group *grp) {
    if (ret == NSS_STATUS_SUCCESS) {
        printf("name=%s, passwd=%s, gid=%d\n", grp->gr_name, grp->gr_passwd, grp->gr_gid);

        char **members = grp->gr_mem;

        if (*members != NULL) {
            printf("\tmembers:\n");

            while (*members != NULL) {
                printf("\tmember=%s\n", *members++);
            }
        }
    } else {
        printf("Failed to get group...\n");
    }

    printf("\n");
}

void test_find_grp_gid(gid_t gid) {
    enum nss_status ret;
    char buffer[BUFFER_LEN];
    struct group grp;
    int _errno = 0;

    ret = _nss_apam_getgrgid_r(gid, &grp, buffer, BUFFER_LEN, &_errno);
    
    printf("gid: %d\n", gid);
    print_grp(ret, &grp);
}

void test_find_grp_name(const char *name) {
    enum nss_status ret;
    char buffer[BUFFER_LEN];
    struct group grp;
    int _errno = 0;

    ret = _nss_apam_getgrnam_r(name, &grp, buffer, BUFFER_LEN, &_errno);

    printf("name: %s\n", name);
    print_grp(ret, &grp);
}

int main(int argc, char** argv) {
    enum nss_status ret;
    struct passwd pwd;
    struct group grp;
    char buffer[BUFFER_LEN];
    int _errno = 0;

while (1) {
    ret = _nss_apam_setpwent(0);

    while (_nss_apam_getpwent_r(&pwd, buffer, BUFFER_LEN, &_errno) == NSS_STATUS_SUCCESS) {
        printf("1: name=%s, dir=%s, shell=%s, passwd=%s, pid=%d\n", pwd.pw_name, pwd.pw_dir, pwd.pw_shell, pwd.pw_passwd, pwd.pw_uid);
    }
    ret = _nss_apam_endpwent();
    printf("\n");

    ret = _nss_apam_setgrent(0);
    while (_nss_apam_getgrent_r(&grp, buffer, BUFFER_LEN, &_errno) == NSS_STATUS_SUCCESS) {
        printf("2: name=%s, passwd=%s, gid=%d\n", grp.gr_name, grp.gr_passwd, grp.gr_gid);
    }
    ret = _nss_apam_endgrent();
    printf("\n");

    ret = _nss_apam_getpwnam_r("mike", &pwd, buffer, BUFFER_LEN, &_errno);

    if (ret == NSS_STATUS_SUCCESS) {
        printf("3: name=%s, dir=%s, shell=%s, passwd=%s, pid=%d\n", pwd.pw_name, pwd.pw_dir, pwd.pw_shell, pwd.pw_passwd, pwd.pw_uid);
    } else {
        printf("Failed to get passwd...\n");
    }
    printf("\n");

    test_find_grp_name("mike");
    test_find_grp_name("apam");
    test_find_grp_gid(5000);

    test_find_grp_gid(50000);
}
    return 0;
}
