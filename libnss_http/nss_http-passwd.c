#include <errno.h>
#include <grp.h>
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

static pthread_mutex_t NSS_HTTP_MUTEX = PTHREAD_MUTEX_INITIALIZER;
#define NSS_HTTP_LOCK()    do { pthread_mutex_lock(&NSS_HTTP_MUTEX); } while (0)
#define NSS_HTTP_UNLOCK()  do { pthread_mutex_unlock(&NSS_HTTP_MUTEX); } while (0)

enum nss_status _nss_http_endpwent(void);
enum nss_status _nss_http_setpwent(int stayopen);
enum nss_status _nss_http_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop);

static enum nss_status
_nss_http_setpwent_locked(int stayopen)
{
    return NSS_STATUS_SUCCESS;
}


// Called to open the passwd file
enum nss_status
_nss_http_setpwent(int stayopen)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_http_setpwent_locked(stayopen);
    NSS_HTTP_UNLOCK();
    return ret;
}


static enum nss_status
_nss_http_endpwent_locked(void)
{
    return NSS_STATUS_SUCCESS;
}


// Called to close the passwd file
enum nss_status
_nss_http_endpwent(void)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_http_endpwent_locked();
    NSS_HTTP_UNLOCK();
    return ret;
}


static enum nss_status
_nss_http_getpwent_r_locked(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    return NSS_STATUS_SUCCESS;
}


// Called to look up next entry in passwd file
enum nss_status
_nss_http_getpwent_r(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_http_getpwent_r_locked(result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}


// Find a passwd by uid
static enum nss_status
_nss_http_getpwuid_r_locked(uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    return NSS_STATUS_SUCCESS;
}


enum nss_status
_nss_http_getpwuid_r(uid_t uid, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_http_getpwuid_r_locked(uid, result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}


static enum nss_status
_nss_http_getpwnam_r_locked(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    return NSS_STATUS_SUCCESS;
}


// Find a passwd by name
enum nss_status
_nss_http_getpwnam_r(const char *name, struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_http_getpwnam_r_locked(name, result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}

