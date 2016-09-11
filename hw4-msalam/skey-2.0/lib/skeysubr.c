/* S/KEY v1.1b (skeysubr.c)
 *
 * Authors:
 *          Neil M. Haller <nmh@thumper.bellcore.com>
 *          Philip R. Karn <karn@chicago.qualcomm.com>
 *          John S. Walden <jsw@thumper.bellcore.com>
 *
 * Modifications:
 *          Scott Chasin <chasin@crimelab.com>
 * changed 2nd line to say include config.h
 * S/KEY misc routines.
 */
 //This has no more Pre-Ansi
#include "skeylibraryfunctions.h"
#include "config.h"

//Not needed for
//#ifdef	__MSDOS__
//#include <dos.h>
//#endif

#ifdef stty
# undef stty
#endif

#ifdef gtty
# undef gtty
#endif


#ifdef HAVE_TERMIO_H
# include <termio.h>
# define TTYSTRUCT termio
# define stty(fd,buf) ioctl((fd),TCSETA,(buf))
# define gtty(fd,buf) ioctl((fd),TCGETA,(buf))
#else
#ifdef HAVE_TERMIOS_H
# include <termios.h>
# define  stty(fd,buf) tcsetattr(STDIN_FILENO,TCSAFLUSH,buf)
# define  gtty(fd,buf) tcgetattr(STDIN_FILENO,buf)
#else
#include <sgtty.h>
# define TTYSTRUCT sgttyb
# define stty(fd,buf) ioctl((fd),TIOCSETN,(buf))
# define gtty(fd,buf) ioctl((fd),TIOCGETP,(buf))
#endif
#endif

#ifdef HAVE_TERMIO_H
    struct termio newtty;
    struct termio oldtty;
#else

#ifdef HAVE_TERMIOS_H
  struct termios newtty;
  struct termios oldtty;
#else
   struct sgttyb newtty;
   struct sgttyb oldtty;
   struct tchars chars;
#endif
#endif

//#ifdef SIGVOID
//#define SIGTYPE void
//#else
//Since SIGTYPE is to be defined either way, i commented out the ifdef. I also commented
//out the ifdef because it was something that I myself did not test for, therefore, the code is now
//better.
#define SIGTYPE void
//#endif

SIGTYPE trapped();

#include "md4.h"
#include "skey.h"

/*#if (defined(__MSDOS__) || defined(MPU8086) || defined(MPU8080) \
    || defined(vax) || defined (MIPSEL))
#define	LITTLE_ENDIAN
#endif*/

//#include <sys/ioctl.h> //This is too fix the warning of implicit delcaration

// #MIRAJ: Functions in which I change the return type to void are when the functions had no type and didn't return anything by the end of it

/* Crunch a key:
 * concatenate the seed and the password, run through MD4 and
 * collapse to 64 bits. This is defined as the user's starting key.
 */
int keycrunch(char * result,char *seed,char *passwd )/* 8-byte result */ /* Seed, any length */ /* Password, any length */
{
  DEBUG_ONENTER
  fprintf(logfile, "Entering function %s(result = \"%s\", seed = \"%s\", passwd = \"%s\")\n",__func__,result,seed, passwd);
	char *buf;
	MDstruct md;
	unsigned int buflen;
#ifdef	WORDS_BIGENDIAN
	int i;
	register long tmp;
#endif


	buflen = strlen(seed) + strlen(passwd);
	if ((buf = (char *)malloc(buflen+1)) == NULL)
		return -1;
	strcpy(buf,seed);
	strcat(buf,passwd);

	/* Crunch the key through MD4 */
	sevenbit(buf);
	MDbegin(&md);
	MDupdate(&md,(unsigned char *)buf,8*buflen);
	free(buf);
	/* Fold result from 128 to 64 bits */
	md.buffer[0] ^= md.buffer[2];
	md.buffer[1] ^= md.buffer[3];

#ifndef	WORDS_BIGENDIAN
	/* Only works on byte-addressed little-endian machines!! */
	memcpy(result,(char *)md.buffer,8);
#else
	/* Default (but slow) code that will convert to
	 * little-endian byte ordering on any machine
	 */

	for (i=0; i<2; i++) {
		tmp = md.buffer[i];
		*result++ = tmp;
		tmp >>= 8;
		*result++ = tmp;
		tmp >>= 8;
		*result++ = tmp;
		tmp >>= 8;
		*result++ = tmp;
	}
#endif

DEBUG_ONEXIT
fprintf(logfile, "Exiting function %s returnvalue is (%d)\n",__func__, 0);

	return 0;
}

/* The one-way function f(). Takes 8 bytes and returns 8 bytes in place */
void f (char *x)
{
  DEBUG_ONENTER
  fprintf(logfile, "Entering function %s(x = \"%s\")\n",__func__,x);

	MDstruct md;
#ifdef	WORDS_BIGENDIAN
	register long tmp;
#endif

	MDbegin(&md);
	MDupdate(&md,(unsigned char *)x,64);

	/* Fold 128 to 64 bits */
	md.buffer[0] ^= md.buffer[2];
	md.buffer[1] ^= md.buffer[3];

#ifndef	WORDS_BIGENDIAN
	/* Only works on byte-addressed little-endian machines!! */
	memcpy(x,(char *)md.buffer,8);

#else
	/* Default (but slow) code that will convert to
	 * little-endian byte ordering on any machine
	 */
	tmp = md.buffer[0];
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;

	tmp = md.buffer[1];
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x++ = tmp;
	tmp >>= 8;
	*x = tmp;
#endif

DEBUG_ONEXIT
fprintf(logfile, "Exiting function %s returnvalue is (%d)\n",__func__, 0);
}

/* Strip trailing cr/lf from a line of text */
void rip (char *buf)
{
  DEBUG_ONENTER
  fprintf(logfile, "Entering function %s(buf = \"%s\")\n",__func__, buf);

	char *cp;

	if((cp = strchr(buf,'\r')) != NULL)
		*cp = '\0';

	if((cp = strchr(buf,'\n')) != NULL)
		*cp = '\0';
  DEBUG_ONEXIT
  fprintf(logfile, "Exiting function %s returnvalue is(%s)\n",__func__, "NO RETURN VALUE FOR VOID FUNCTION");

}

/*#ifdef	__MSDOS__

char *readpass(char *buf, int n)
{
  int i;
  char *cp;

  for (cp=buf,i = 0; i < n ; i++)
       if ((*cp++ = bdos(7,0,0)) == '\r')
          break;
   *cp = '\0';
   putchar('\n');
   rip(buf);
   return buf;


}
#else
*/
char *readpass (char *buf,int n)
{

    DEBUG_ONENTER
    fprintf(logfile, "Entering function %s(buf = \"%s\", n = %d)\n",__func__, buf,n);

    if(!echoon){
    set_term ();
    echo_off ();
    }
 //#endif

//old code was just fgets (buf, n, stdin);
//I added error checking
    if (fgets (buf, n, stdin)== NULL){
      fprintf(stderr, "fgets failed");
      exit(1);
    }

    rip (buf);

    printf ("\n\n");
    sevenbit (buf);

    if(!echoon){
    unset_term ();
    }

    DEBUG_ONEXIT
    fprintf(logfile, "Exiting function %s returnvalue is(buf = \"%s\")\n",__func__, buf);

    return buf;
}

void set_term ()// #MIRAJ: changed return type to void
{
  DEBUG_ONENTER
  fprintf(logfile, "Entering function %s(%s)\n",__func__, "NO PARAMETERS IN THIS FUNCTION");

    gtty (fileno(stdin), &newtty);
    gtty (fileno(stdin), &oldtty);

    signal (SIGINT, trapped);

   DEBUG_ONEXIT
   fprintf(logfile, "Exiting function %s returnvalue is(%s)\n",__func__, "NO RETURN VALUE FOR VOID FUNCTION");
}

void echo_off () // #MIRAJ: changed return type to void
{
  DEBUG_ONENTER
  fprintf(logfile, "Entering function %s(%s)\n",__func__, "NO PARAMETERS IN THIS FUNCTION");

#ifdef HAVE_TERMIO_H
    newtty.c_lflag &= ~(ICANON | ECHO | ECHONL);
#else
#ifdef HAVE_TERMIOS_H
    newtty.c_lflag &= ~(ICANON | ECHO | ECHONL);

#else
    newtty.sg_flags |= CBREAK;
    newtty.sg_flags &= ~ECHO;
#endif
#endif

#ifdef HAVE_TERMIO_H
    newtty.c_cc[VMIN] = 1;
    newtty.c_cc[VTIME] = 0;
    newtty.c_cc[VINTR] = 3;
#else
#ifdef HAVE_TERMIOS_H
    newtty.c_cc[VMIN] = 1;
    newtty.c_cc[VTIME] = 0;
    newtty.c_cc[VINTR] = 3;
#else
    ioctl(fileno(stdin), TIOCGETC, &chars);
    chars.t_intrc = 3;
    ioctl(fileno(stdin), TIOCSETC, &chars);
#endif
#endif
    stty (fileno (stdin), &newtty);

    DEBUG_ONEXIT
    fprintf(logfile, "Exiting function %s returnvalue is(%s)\n",__func__, "NO RETURN VALUE FOR VOID FUNCTION");
}

void unset_term () // #MIRAJ: changed return type to void
{
  DEBUG_ONENTER
  fprintf(logfile, "Entering function %s(%s)\n",__func__, "NO PARAMETERS IN THIS FUNCTION");

    stty (fileno (stdin), &oldtty);

#ifndef HAVE_TERMIO_H
#ifndef HAVE_TERMIOS_H
    ioctl(fileno(stdin), TIOCSETC, &chars);
#endif
#endif

DEBUG_ONEXIT
fprintf(logfile, "Exiting function %s returnvalue is(%s)\n",__func__, "NO RETURN VALUE FOR VOID FUNCTION");
}

void trapped()
 {
   DEBUG_ONENTER
   fprintf(logfile, "Entering function %s(%s)\n",__func__, "NO PARAMETERS IN THIS FUNCTION");

  signal (SIGINT, trapped);
  printf ("^C\n");
  unset_term ();
  DEBUG_ONEXIT
  fprintf(logfile, "Exiting function %s returnvalue is(%s)\n",__func__, "NO RETURN VALUE FOR VOID FUNCTION");
  exit (-1);

 }

//#endif

/* removebackspaced over charaters from the string */
void backspace(char *buf) // #MIRAJ: changed return type to void
{
  DEBUG_ONENTER
  fprintf(logfile, "Entering function %s(buf = %s)\n",__func__, buf);

	char bs = 0x8;
	char *cp = buf;
	char *out = buf;

	while(*cp){
		if( *cp == bs ) {
			if(out == buf){
				cp++;
				continue;
			}
			else {
			  cp++;
			  out--;
			}
		}
		else {
			*out++ = *cp++;
		}

	}
	*out = '\0';
  DEBUG_ONEXIT
  fprintf(logfile, "Exiting function %s returnvalue is(%s)\n",__func__, "NO RETURN VALUE FOR VOID FUNCTION");

}

/* sevenbit ()
 *
 * Make sure line is all seven bits.
 */

void sevenbit (char *s) // #MIRAJ: changed return type to void
{
  DEBUG_ONENTER
  fprintf(logfile, "Entering function %s(s = \"%s\")\n",__func__, s);
   while (*s) {
     *s = 0x7f & ( *s);
     s++;

   }
   DEBUG_ONEXIT
  fprintf(logfile, "Exiting function %s returnvalue is(%s)\n",__func__, "NO RETURN VALUE FOR VOID FUNCTION");

}
