/* S/KEY v1.1b (skeysh.c)
 *
 * Authors:
 *          Neil M. Haller <nmh@thumper.bellcore.com>
 *          Philip R. Karn <karn@chicago.qualcomm.com>
 *          John S. Walden <jsw@thumper.bellcore.com>
 *          Scott Chasin <chasin@crimelab.com>
 *
 * S/Key authentication shell
 */

#include"skeylibraryfunctions.h"
#include "skey.h"
char userbuf[16] = "USER=";
char homebuf[128] = "HOME=";
char shellbuf[128] = "SHELL=";
char pathbuf[128] = "PATH=:/usr/ucb:/bin:/usr/bin";
char *cleanenv[] = { userbuf, homebuf, shellbuf, pathbuf, 0, 0 };
char *shell = "/bin/csh";

#ifndef HAVE_SETENV
void setenv (char *ename, char  *eval, char *buf);
#endif

#include <grp.h>  //#MIRAJ this has initgroups I think
//End forward declarations here


extern char **environ;
struct passwd *pwd;

// #NOTE TO SELF, this will be important to make sure configure.ac checks for
#ifndef HAVE_GETENV
char *getenv(char *ename)
{
  register char *cp, *dp;
  register char **ep = environ;

  while ((dp = *ep++)) {  // #MIRAJ Was the single = intentional? Ask. I put the parentheses myself
         for (cp = ename; *cp == *dp && *cp; cp++, dp++)
              continue;
         if (*cp == 0 && (*dp == '=' || *dp == 0))
              return (*--ep);
  }
  return ((char *)0);
}
#endif

int main (int argc,char *argv[])
{
  int stat;  //, pid; //pid was marked as unused, was getting warning, so i just commented it out
  char user [8];

  if ((pwd = getpwuid(getuid())) == NULL) {
      fprintf(stderr, "Who are you?\n");
      return 1;
  }

  strcpy(user, pwd->pw_name);

  if ((pwd = getpwnam(user)) == NULL) {
      fprintf(stderr, "Unknown login: %s\n", user);
      return 1;
  }

  stat = skey_haskey (user);

  if (stat == 1) {
     fprintf(stderr,"keysh: no entry for user %s.\n", user);
     return -1;
  }

  if (stat == -1) {
     fprintf(stderr, "keysh: could not open key file.\n");
     return -1;
  }

  if (skey_authenticate (user) == -1) {
      printf ("Invalid response.\n");
      return -1;
  }

  if (setgid(pwd->pw_gid) < 0) {
      perror("keysh: setgid");
      return 3;
  }

  if (initgroups(user, pwd->pw_gid)) {
      fprintf(stderr, "keysh: initgroups failed\n");
      return 4;
  }

  if (setuid(pwd->pw_uid) < 0) {
      perror("keysh: setuid");
      return 5;
  }

  cleanenv[4] = getenv("TERM");
  environ = cleanenv;

// #MARKER TO SELF
#ifndef HAVE_SETENV
  setenv("USER", pwd->pw_name, userbuf);
  setenv("SHELL", shell, shellbuf);
  setenv("HOME", pwd->pw_dir, homebuf);
#else
  setenv("USER","PARAMTERNOTNEEDED",0);
  setenv("SHELL","PARAMTERNOTNEEDED",0);
  setenv("HOME","PARAMTERNOTNEEDED",0);

#endif

  if (chdir(pwd->pw_dir) < 0) {
      fprintf(stderr, "No directory\n");
      return 6;
  }

  execv (shell, argv);
  fprintf(stderr, "No shell\n");
  return 7;
}

#ifndef HAVE_SETENV
void setenv (char *ename, char  *eval, char *buf)
{
  register char *cp, *dp;
  register char **ep = environ;

  /*
   * this assumes an environment variable "ename" already exists
   */
  while ((dp = *ep++)) { // #MIRAJ Was the single = intentional? Ask. Put parentheses to force it to be
       for (cp = ename; *cp == *dp && *cp; cp++, dp++)
            continue;
       if (*cp == 0 && (*dp == '=' || *dp == 0)) {
            strcat(buf, eval);
            *--ep = buf;
            return;
       }
   }
}
#endif
