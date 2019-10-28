#include <errno.h>
#include <jansson.h>
#include <nss.h>
#include <pthread.h>
#include <pwd.h>
#include <shadow.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "group-util.h"

static pthread_mutex_t NSS_HTTP_MUTEX = PTHREAD_MUTEX_INITIALIZER;
#define NSS_HTTP_LOCK()    do { pthread_mutex_lock(&NSS_HTTP_MUTEX); } while (0)
#define NSS_HTTP_UNLOCK()  do { pthread_mutex_unlock(&NSS_HTTP_MUTEX); } while (0)

enum nss_status _nss_http_endgrent(void);
enum nss_status _nss_http_setgrent(int stayopen);
enum nss_status _nss_http_getgrent_r(struct group *result, char *buffer, size_t buflen, int *errnop);

enum nss_status
_nss_http_setgrent_locked(int stayopen)
{
    load_group();
    return NSS_STATUS_SUCCESS;
}


// Called to open the group file
enum nss_status
_nss_http_setgrent(int stayopen)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_http_setgrent_locked(stayopen);
    NSS_HTTP_UNLOCK();
    return ret;
}


enum nss_status
_nss_http_endgrent_locked(void)
{
    // do nothing
    return NSS_STATUS_SUCCESS;
}


// Called to close the group file
enum nss_status
_nss_http_endgrent(void)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_http_endgrent_locked();
    NSS_HTTP_UNLOCK();
    return ret;
}

static void copy_group(struct group *result, char *buffer, size_t buflen, struct group *grp) {
    char  *buf = buffer;
    size_t len = buflen;
    size_t tlen = 0;

    result->gr_name  = strncpy(buf, grp->gr_name, len);
    tlen = strlen(result->gr_name) + 1;
    len -= tlen;
    buf += tlen;

    result->gr_passwd  = strncpy(buf, grp->gr_passwd, len);
    tlen = strlen(result->gr_passwd) + 1;
    len -= tlen;
    buf += tlen;

    result->gr_gid   = grp->gr_gid;
}

enum nss_status
_nss_http_getgrent_r_locked(struct group *result, char *buffer, size_t buflen, int *errnop)
{
    struct group *grp = get_next_group();

    if (grp == NULL) {
        return NSS_STATUS_NOTFOUND;
    }

    copy_group(result, buffer, buflen, grp);

    return NSS_STATUS_SUCCESS;
}


// Called to look up next entry in group file
enum nss_status
_nss_http_getgrent_r(struct group *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_http_getgrent_r_locked(result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}


// Find a group by gid
enum nss_status
_nss_http_getgrgid_r_locked(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    struct group *grp = find_grp_gid(gid);

    if (grp == NULL) {
        return NSS_STATUS_NOTFOUND;
    }

    copy_group(result, buffer, buflen, grp);

    return NSS_STATUS_SUCCESS;
}


enum nss_status
_nss_http_getgrgid_r(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_http_getgrgid_r_locked(gid, result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}


enum nss_status
_nss_http_getgrnam_r_locked(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    struct group *grp = find_grp_name(name);

    if (grp == NULL) {
        return NSS_STATUS_NOTFOUND;
    }

    copy_group(result, buffer, buflen, grp);

    return NSS_STATUS_SUCCESS;
}


// Find a group by name
enum nss_status
_nss_http_getgrnam_r(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_http_getgrnam_r_locked(name, result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}

