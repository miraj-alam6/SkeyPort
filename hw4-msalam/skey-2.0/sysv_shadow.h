#include <shadow.h>

struct spwd *spwd;

static struct passwd *fix_getpwnam(u)
char   *u;
{
    struct passwd *pwd = 0;

    if ((spwd = getspnam(u)) && (pwd = getpwnam(u)))
	pwd->pw_passwd = spwd->sp_pwdp;
    return pwd;
}

#define getpwnam fix_getpwnam

extern int  sysv_expire(struct spwd *);  //I changed this to an int because that's what it is. Probably should make this no longer an extern
