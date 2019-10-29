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

int main(int argc, char** argv) {
    enum nss_status ret;
    struct passwd pwd;
    struct group grp;
    char buffer[BUFFER_LEN];
    int _errno = 0;

while (1) {
    ret = _nss_apam_setpwent(0);

    while (_nss_apam_getpwent_r(&pwd, buffer, BUFFER_LEN, &_errno) == NSS_STATUS_SUCCESS) {
        printf("name=%s, dir=%s, shell=%s, passwd=%s\n", pwd.pw_name, pwd.pw_dir, pwd.pw_shell, pwd.pw_passwd);
    }
    ret = _nss_apam_endpwent();
    printf("\n");


    ret = _nss_apam_setgrent(0);
    while (_nss_apam_getgrent_r(&grp, buffer, BUFFER_LEN, &_errno) == NSS_STATUS_SUCCESS) {
        printf("name=%s, passwd=%s, gid=%d\n", grp.gr_name, grp.gr_passwd, grp.gr_gid);
    }
    ret = _nss_apam_endgrent();
    printf("\n");


}
    return 0;
}
