/*
 * S/KEY v1.1b (skey.h)
 *
 * Authors:
 *          Neil M. Haller <nmh@thumper.bellcore.com>
 *          Philip R. Karn <karn@chicago.qualcomm.com>
 *          John S. Walden <jsw@thumper.bellcore.com>
 *
 * Modifications:
 *          Scott Chasin <chasin@crimelab.com>
 *
 * Main client header
 */

#define setpriority(x,y,z)

#include "skeylibraryfunctions.h"



/* Server-side data structure for reading keys file during login */
struct skey
{
  FILE *keyfile;
  char buf[256];
  char *logname;
  int n;
  char *seed;
  char *val;
  long recstart;		/* needed so reread of buffer is efficient */


};

/* Client-side structure for scanning data stream for challenge */
struct mc
{
  char buf[256];
  int skip;
  int cnt;
};

void f(char *x);
int keycrunch(char *result, char *seed, char *passwd);
char *btoe(char *engout, char *c);
char *put8(char *out, char *s);
int etob(char *out, char *e);
void rip(char *buf);
int skeychallenge(struct skey * mp, char *name, char *ss);
int skeylookup(struct skey * mp, char *name);
int skeyverify (struct skey * mp, char *response);
int skey_authenticate (char *username); // This is in skeylogin
int skey_haskey (char *username);  // Same as above

//#MIRAJ the following functions I am making headers for, but there bodies are not actually defined by me.
int atob8(char *out, char *in);
void backspace(char *buf);
int btoa8(char *out, char *in);
void sevenbit (char *s);
int htoi(register int c);
char *readpass(char *buf, int n); //this is from skeysubr.c
void unset_term();
void set_term();
void echo_off();
void usage (char *s);

extern int debuglevel;
extern int echoon;
extern FILE *logfile;
//VERY IMPORTANT NOTE ON HOW TO USE DEBUG_ONENTER AND DEBUG_ONEXIT, both macros MUST be followed by another
//statement that is meant to execute based on the condition as indicated by the ends of each of the macros
#define DEBUG_ONENTER if(debuglevel == 1 || debuglevel == 2) \
fprintf(logfile, "Entering function %s\n",__func__ );\
else if (debuglevel == 3)

#define DEBUG_ONEXIT if(debuglevel == 1) \
fprintf(logfile, "Exiting function %s\n",__func__ );\
else if (debuglevel == 2 || debuglevel == 3)
