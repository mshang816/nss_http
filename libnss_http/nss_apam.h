#include <nss.h>
#include <pwd.h>
#include <grp.h>

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
