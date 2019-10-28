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

enum nss_status
_nss_http_setspent_locked(int stayopen)
{
    return NSS_STATUS_SUCCESS;
}


// Called to open the shadow file
enum nss_status
_nss_http_setspent(int stayopen)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_http_setspent_locked(stayopen);
    NSS_HTTP_UNLOCK();
    return ret;
}


enum nss_status
_nss_http_endspent_locked(void)
{
    return NSS_STATUS_SUCCESS;
}


// Called to close the shadow file
enum nss_status
_nss_http_endspent(void)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_http_endspent_locked();
    NSS_HTTP_UNLOCK();
    return ret;
}


enum nss_status
_nss_http_getspent_r_locked(struct spwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret = NSS_STATUS_SUCCESS;
    return ret;
}


// Called to look up next entry in shadow file
enum nss_status
_nss_http_getspent_r(struct spwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_http_getspent_r_locked(result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}


enum nss_status
_nss_http_getspnam_r_locked(const char *name, struct spwd *result, char *buffer, size_t buflen, int *errnop)
{
    return NSS_STATUS_SUCCESS;
}


// Find a shadow by name
enum nss_status
_nss_http_getspnam_r(const char *name, struct spwd *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_HTTP_LOCK();
    ret = _nss_http_getspnam_r_locked(name, result, buffer, buflen, errnop);
    NSS_HTTP_UNLOCK();
    return ret;
}

