/*
 * S/KEY v1.1b (skey.c)
 *
 * Authors:
 *          Neil M. Haller <nmh@thumper.bellcore.com>
 *          Philip R. Karn <karn@chicago.qualcomm.com>
 *          John S. Walden <jsw@thumper.bellcore.com>
 *          Scott Chasin <chasin@crimelab.com>
 *
 *
 * Stand-alone program for computing responses to S/Key challenges.
 * Takes the iteration count and seed as command line args, prompts
 * for the user's key, and produces both word and hex format responses.
 *
 * Usage example:
 *	>skey 88 ka9q2
 *	Enter password:
 *	OMEN US HORN OMIT BACK AHOY
 *	>
 */

//I think I removed all Pre-Ansi from here

#include "skeylibraryfunctions.h"
#define VERSION_NUMBER 2.0

//Commented it out because shouldn't have any system specific, and no need for MSDOS
//but might be important for next assignment
//#ifdef	__MSDOS__
//#include <dos.h>
//#else				/* Assume BSD unix */
//these are moved to skeylibraryfunctions.h
//#include <fcntl.h>
//#include <sgtty.h>
//#endif
#include "md4.h"
#include "skey.h"

//GOT RID OF THESE NEXT TWO LINES BECAUSE THESE FORWARD DECLARATIONS ARE NOT NECCESSARY BECAUSE OF OUR INCLUDE
//char *readpass ();
//int getopt ();
void usage ();


// GOT RID OF FOLLOWING TWO EXTERNS BECAUSE THE INCLUDES WILL HANDLE THEM
//extern int optind;
//extern char *optarg;


int main (int argc, char *argv[])
{

  logfile = stdout;
  //Start all flags at 0, and set the ones gotten from command line to 1 later during getopt
  int opt_d = 0;
  int opt_h = 0;
  int opt_v = 0;
  //int opt_l = 0;

  int n, cnt, i, pass = 0;
  char passwd[256], key[8], buf[33], *seed, *slash;
  int index;

  //I added code to zero out the buffers
  for(index = 0; index < 8; index++){
    key[index] = 0;
  }
  for(index = 0; index < 256; index++){
    passwd[index] = 0;
  }
  for(index = 0; index <33; index++){
    buf[index] = 0;
  }


  cnt = 1;
  //printf("Got here 1\n");
  while ((i = getopt (argc, argv, "dehvn:p:l:")) != EOF)
  {
    switch (i)
    {
    case 'd':{
      opt_d++;
      break;
      }
    case 'h':{
        opt_h = 1;
        break;
      }
    case 'v':{
      opt_v = 1;
      break;
    }
    case 'e':{
      echoon = 1;
      break;
      }
    case 'n':{
      cnt = atoi (optarg);
//      printf("Never get here\n");
      break;
      }
    case 'p':{
      strcpy (passwd, optarg);
//      printf("Never get here\n");
      pass = 1;
      break;
      }
    case 'l':{
      //use optarg here to make a logging file
//      opt_l = 1;
      logfile = fopen((const char *)optarg, "w");
      fclose(logfile);
      logfile = fopen((const char *)optarg, "a");
      break;

      }

    }
  }

  if(opt_d > 3){
    opt_d = 3;
  }
  debuglevel = opt_d;

  DEBUG_ONENTER
  {
    fprintf(logfile, "Entering function %s(argc = %d argv = {",__func__, argc);
    for(index =0; index < argc; index ++){
      fprintf(logfile, "  %s  ",argv[index]);
    }
    fprintf(logfile, "})\n");
  }

  printf("Debugging Level: %d\n", debuglevel);

  //Process all of the getopt things here
  if (opt_v){
    fprintf(stderr,"VERSION NUMBER %.2f\n",VERSION_NUMBER);
  }

  if (opt_h){
    usage("./key");

  }

  /* could be in the form <number>/<seed> */

  if (argc <= optind + 1)
  {
    /* look for / in it */
    if (argc <= optind)
    {
      usage (argv[0]);
      exit (1);
    }

    slash = strchr (argv[optind], '/');
    if (slash == NULL)
    {
      usage (argv[0]);
      exit (1);
    }
    *slash++ = '\0';
    seed = slash;

    if ((n = atoi (argv[optind])) < 0)
    {
      printf ("%s not positive\n", argv[optind]);
      usage (argv[0]);
      exit (1);
    }
  }
  else
  {

    if ((n = atoi (argv[optind])) < 0)
    {
      printf ("%s not positive\n", argv[optind]);
      usage (argv[0]);
      exit (1);
    }
    seed = argv[++optind];
  }

  /* Get user's secret password */
  if (!pass)
  {
    printf ("Enter secret password: ");
    readpass (passwd, sizeof (passwd));
  }

  rip (passwd);

  /* Crunch seed and password into starting key */
  if (keycrunch (key, seed, passwd) != 0)
  {
    fprintf (stderr, "%s: key crunch failed\n", argv[0]);
    exit (1);
  }
  if (cnt == 1)
  {
    while (n-- != 0)
      f (key);
    printf ("%s\n", btoe (buf, key));
#ifdef	HEXIN
    printf ("%s\n", put8 (buf, key));
#endif
   }
  else
  {
    for (i = 0; i <= n - cnt; i++)
      f (key);
    for (; i <= n; i++)
    {
#ifdef	HEXIN
      printf ("%d: %-29s  %s\n", i, btoe (buf, key), put8 (buf, key));
#else
      printf ("%d: %-29s\n", i, btoe (buf, key));
#endif
      f (key);
    }
  }
  DEBUG_ONEXIT
  fprintf(logfile, "Exiting function %s (returnvalue is = %d)\n",__func__, 0);
  exit (0);
}

void usage (char *s)  //Removed Pre-Ansi from here, if anything went wrong, revert back

{
  DEBUG_ONENTER
  fprintf(logfile, "Entering function %s(s = \"%s\")\n",__func__, s);

  printf("Usage: %s [-h] [-e] [-ddd] [-v] [-l logfile] [-n count] [-p password ] <sequence #>[/] <key> \n", s);

  DEBUG_ONEXIT
  fprintf(logfile, "Exiting function %s (returnvalue is = %s)\n",__func__, "NO RETURN VALUE FOR VOID FUNCTION");
}
