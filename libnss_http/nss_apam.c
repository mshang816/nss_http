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
#include "pwdgrp-util.h"
#include "nss_apam.h"

static pthread_mutex_t NSS_APAM_MUTEX = PTHREAD_MUTEX_INITIALIZER;
#define NSS_APAM_LOCK()    do { pthread_mutex_lock(&NSS_APAM_MUTEX); } while (0)
#define NSS_APAM_UNLOCK()  do { pthread_mutex_unlock(&NSS_APAM_MUTEX); } while (0)

#define USER_SHELL          "/bin/bash"
#define USER_NOSHELL        "/sbin/nologin"
#define USER_PASSWD         "*"
#define USER_DIR            "/var/home"
#define USER_GECOS          "Dynamic User"

static enum nss_status
_nss_apam_setpwent_locked(int stayopen)
{
    load_all_entries(NULL);
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
    free_all_entries();
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

#define SECONDS_BEFORE_EXP  (2*60)
#define BUFFER_LENGTH       512

static void copy_passwd(struct passwd *result, char *buffer, size_t buflen, struct user_entry *ent) {
    time_t now = time(NULL);

    char  *buf = buffer;
    size_t len = buflen;
    size_t tlen = 0;

    result->pw_name  = strncpy(buf, ent->name, len);
    tlen = strlen(ent->name) + 1;
    len -= tlen;
    buf += tlen;

    result->pw_uid   = ent->uid;
    result->pw_gid   = ent->uid;

    result->pw_gecos  = (char*) USER_GECOS;
    result->pw_passwd = (char*) USER_PASSWD;
    
    if (ent->create_time + SECONDS_BEFORE_EXP > now) {
        result->pw_shell  = (char*) USER_SHELL;
    } else {
        // expired
        result->pw_shell  = (char*) USER_NOSHELL;
    }

    char dir[BUFFER_LENGTH];

    sprintf(dir, "%s/%s", USER_DIR, ent->name);

    result->pw_dir = strncpy(buf, dir, len);
    tlen = strlen(result->pw_dir) + 1;
    len -= tlen;
    buf += tlen;
}

static enum nss_status
_nss_apam_getpwent_r_locked(struct passwd *result, char *buffer, size_t buflen, int *errnop)
{
    memset(buffer, '\0', buflen);

    struct user_entry *ent = get_next_user_entry();

    if (ent == NULL) {
        return NSS_STATUS_NOTFOUND;
    }

    copy_passwd(result, buffer, buflen, ent);

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

    struct user_entry *ent = find_entry_uid(uid);

    if (ent == NULL) {
        return NSS_STATUS_NOTFOUND;
    }

    copy_passwd(result, buffer, buflen, ent);
    free_entry(ent);

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

    struct user_entry *ent = find_entry_name(name);

    if (ent == NULL) {
        return NSS_STATUS_NOTFOUND;
    }

    copy_passwd(result, buffer, buflen, ent);
    free_entry(ent);

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

// --------------------------------------------------------------------------
//                               handling groups
// --------------------------------------------------------------------------
enum nss_status
_nss_apam_setgrent_locked(int stayopen)
{
    load_all_entries(NULL);
    return NSS_STATUS_SUCCESS;
}


// Called to open the group file
enum nss_status
_nss_apam_setgrent(int stayopen)
{
    enum nss_status ret;
    NSS_APAM_LOCK();
    ret = _nss_apam_setgrent_locked(stayopen);
    NSS_APAM_UNLOCK();
    return ret;
}


enum nss_status
_nss_apam_endgrent_locked(void)
{
    free_all_entries();
    return NSS_STATUS_SUCCESS;
}


// Called to close the group file
enum nss_status
_nss_apam_endgrent(void)
{
    enum nss_status ret;
    NSS_APAM_LOCK();
    ret = _nss_apam_endgrent_locked();
    NSS_APAM_UNLOCK();
    return ret;
}

static void copy_group(struct group *result, char *buffer, size_t buflen, struct user_entry *ent) {
    char  *buf = buffer;
    size_t len = buflen;
    size_t tlen = 0;

    result->gr_name  = strncpy(buf, ent->name, len);
    tlen = strlen(result->gr_name) + 1;
    len -= tlen;
    buf += tlen;

    result->gr_mem = (char**) buf;
    tlen = sizeof(char*);
    len -= tlen;
    buf += tlen;

    result->gr_passwd = USER_PASSWD;
    result->gr_gid    = ent->uid;
}

enum nss_status
_nss_apam_getgrent_r_locked(struct group *result, char *buffer, size_t buflen, int *errnop)
{
    memset(buffer, '\0', buflen);

    struct user_entry *ent = get_next_user_entry();

    if (ent == NULL) {
        return NSS_STATUS_NOTFOUND;
    }

    copy_group(result, buffer, buflen, ent);

    return NSS_STATUS_SUCCESS;
}


// Called to look up next entry in group file
enum nss_status
_nss_apam_getgrent_r(struct group *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_APAM_LOCK();
    ret = _nss_apam_getgrent_r_locked(result, buffer, buflen, errnop);
    NSS_APAM_UNLOCK();
    return ret;
}


// Find a group by gid
enum nss_status
_nss_apam_getgrgid_r_locked(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    memset(buffer, '\0', buflen);

    struct user_entry *ent = find_entry_uid(gid);

    if (ent == NULL) {
        return NSS_STATUS_NOTFOUND;
    }

    copy_group(result, buffer, buflen, ent);
    free_entry(ent);

    return NSS_STATUS_SUCCESS;
}


enum nss_status
_nss_apam_getgrgid_r(gid_t gid, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_APAM_LOCK();
    ret = _nss_apam_getgrgid_r_locked(gid, result, buffer, buflen, errnop);
    NSS_APAM_UNLOCK();
    return ret;
}


enum nss_status
_nss_apam_getgrnam_r_locked(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    memset(buffer, '\0', buflen);

    struct user_entry *ent = find_entry_name(name);

    if (ent == NULL) {
        return NSS_STATUS_NOTFOUND;
    }

    copy_group(result, buffer, buflen, ent);
    free_entry(ent);

    return NSS_STATUS_SUCCESS;
}


// Find a group by name
enum nss_status
_nss_apam_getgrnam_r(const char *name, struct group *result, char *buffer, size_t buflen, int *errnop)
{
    enum nss_status ret;
    NSS_APAM_LOCK();
    ret = _nss_apam_getgrnam_r_locked(name, result, buffer, buflen, errnop);
    NSS_APAM_UNLOCK();
    return ret;
}

