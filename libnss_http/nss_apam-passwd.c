#include <errno.h>
#include <nss.h>
#include <pthread.h>
#include <pwd.h>
#include <shadow.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "passwd-util.h"
#include "nss_apam.h"

static pthread_mutex_t NSS_APAM_MUTEX = PTHREAD_MUTEX_INITIALIZER;
#define NSS_APAM_LOCK()    do { pthread_mutex_lock(&NSS_APAM_MUTEX); } while (0)
#define NSS_APAM_UNLOCK()  do { pthread_mutex_unlock(&NSS_APAM_MUTEX); } while (0)

static enum nss_status
_nss_apam_setpwent_locked(int stayopen)
{
    load_passwd();
    return NSS_STATUS_SUCCESS;
}


// Called to open the passwd file
enum nss_status
_nss_apam_setpwent(int stayopen)
{
    enum nss_status ret;
    NSS_APAM_LOCK();
    ret = _nss_apam_setpwent_locked(stayopen);
    NSS_APAM_UNLOCK();
    return ret;
}


static enum nss_status
_nss_apam_endpwent_locked(void)
{
    free_all_passwd();
    return NSS_STATUS_SUCCESS;
}


// Called to close the passwd file
enum nss_status
_nss_apam_endpwent(void)
{
    enum nss_status ret;
    NSS_APAM_LOCK();
    ret = _nss_apam_endpwent_locked();
    NSS_APAM_UNLOCK();
    return ret;
}

static void copy_passwd(struct passwd *result, char *buffer, size_t buflen, struct passwd *pwd) {
    char  *buf = buffer;
    size_t len = buflen;
    size_t tlen = 0;

    result->pw_name  = strncpy(buf, pwd->pw_name, len);
    tlen = strlen(result->pw_name) + 1;
    len -= tlen;
    buf += tlen;

    /*
    result->pw_dir   = strncpy(buf, pwd->pw_dir, len);
    tlen = strlen(result->pw_dir) + 1;
    len -= tlen;
    buf += tlen;

    result->pw_shell = strncpy(buf, pwd->pw_shell, len);
    tlen = strlen(result->pw_shell) + 1;
    len -= tlen;
    buf += tlen;
    */

    result->pw_uid   = pwd->pw_uid;
    result->pw_gid   = pwd->pw_gid;

    result->pw_gecos  = (char*) DYNAMIC_USER_GECOS;
    result->pw_passwd = (char*) DYNAMIC_USER_PASSWD;
    result->pw_shell  = (char*) DYNAMIC_USER_SHELL;
    result->pw_dir    = (char*) DYNAMIC_USER_DIR;
}

static enum nss_status
_nss_apam_getpwent_r_locked(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    memset(buffer, '\0', buflen);

    struct passwd* pwd = get_next_passwd();

    if (pwd == NULL) {
        return NSS_STATUS_NOTFOUND;
    }

    copy_passwd(result, buffer, buflen, pwd);

    return NSS_STATUS_SUCCESS;
}


// Called to look up next entry in passwd file
enum nss_status
_nss_apam_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_APAM_LOCK();
    ret = _nss_apam_getpwent_r_locked(result, buffer, buflen, errnop);
    NSS_APAM_UNLOCK();
    return ret;
}


// Find a passwd by uid
static enum nss_status
_nss_apam_getpwuid_r_locked(uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    memset(buffer, '\0', buflen);

    struct passwd *pwd = find_pwd_uid(uid);

    if (pwd == NULL) {
        return NSS_STATUS_NOTFOUND;
    }

    copy_passwd(result, buffer, buflen, pwd);

    return NSS_STATUS_SUCCESS;
}


enum nss_status
_nss_apam_getpwuid_r(uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_APAM_LOCK();
    ret = _nss_apam_getpwuid_r_locked(uid, result, buffer, buflen, errnop);
    NSS_APAM_UNLOCK();
    return ret;
}


static enum nss_status
_nss_apam_getpwnam_r_locked(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    memset(buffer, '\0', buflen);

    struct passwd *pwd = find_pwd_name(name);

    if (pwd == NULL) {
        return NSS_STATUS_NOTFOUND;
    }

    copy_passwd(result, buffer, buflen, pwd);

    return NSS_STATUS_SUCCESS;
}


// Find a passwd by name
enum nss_status
_nss_apam_getpwnam_r(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_APAM_LOCK();
    ret = _nss_apam_getpwnam_r_locked(name, result, buffer, buflen, errnop);
    NSS_APAM_UNLOCK();
    return ret;
}

