/*
 * password.c
 * implements safe password change non-interactive
 *
 * $Id: password.c,v 1.7 1999/03/25 22:13:26 eric Exp $
 */

#include <shadow.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#include "password.h"

typedef enum {add, delete, modify} Action_t;

#define BUFFER_SIZE 2048

static int error_save; /* keep from clobbering errno */

long
_n_days_epoch() {
  time_t curtime;
  long   days;

  curtime = time(0);
  days = (curtime)/86400;
  return (days);
}

int
_file_copy(char *from, char *to, mode_t mode, mode_t final_mode) {
  int  fpr;
  int  fpw;
  int  n_bytes = 1;
  char buffer[BUFFER_SIZE];

  fpr = open(from, O_RDONLY);
  if (fpr == -1) {
    return(fpr);
  }
  fpw = open(to, O_WRONLY|O_CREAT, mode);
  if (fpw == -1) {
    error_save = errno;
    close(fpr);
    return(fpw);
  }
  while (n_bytes != 0) {
    n_bytes = read(fpr, (void *)buffer, BUFFER_SIZE);
    if (n_bytes < 0) {
      error_save = errno;
      close(fpr);
      close(fpw);
      return(n_bytes);
    }
    n_bytes = write(fpw, (void *)buffer, n_bytes);
    if (n_bytes < 0) {
      error_save = errno;
      close(fpr);
      close(fpw);
      return(n_bytes);
    }
  }
  close(fpr);
  fchmod(fpw, final_mode);
  close(fpw);
  return 0;
}
int
_write_pass_shadow(Action_t action, char *login, char *pentry, char *sentry) {
  int  error;
  int  login_len;
  char buffer[BUFFER_SIZE];
  FILE *fp = 0;
  FILE *fpr = 0;

  login_len = strlen(login);
  error = lckpwdf();
  if (error == -1) {
    syslog(LOG_ERR, "couldn't obtain passwd/shadow lock : %m");
    errno = error_save;
    return error;
  }
  error_save = 0;
  /* back-up current shadow and passwd */
  error = _file_copy("/etc/passwd", "/etc/opasswd_a", 0644, 0444);
  if (error != 0) {
    syslog(LOG_ERR, "couldn't backup passwd : %m");
    errno = error_save;
    goto DONE_WPS;
  }
  error = _file_copy("/etc/shadow", "/etc/oshadow_a", 0600, 0400);
  if (error != 0) {
    syslog(LOG_ERR, "couldn't backup shadow : %m");
    errno = error_save;
    goto DONE_WPS;
  }
  switch(action) {
  case add: {
    fp = fopen("/etc/passwd","a");
    if (fp == (FILE *)0) {
      error_save = errno;
      syslog(LOG_ERR, "couldn't open /etc/passwd for appending : %m");
      goto DONE_WPS;
    }
    error = fprintf(fp,"%s\n",pentry);
    if (error < 0) {
      error_save = errno;
      syslog(LOG_ERR, "couldn't write to /etc/passwd : %m");
      goto BACK_OUT;
    }
    fclose(fp);
    fp = fopen("/etc/shadow","a");
    if (fp == (FILE *)0) {
      error_save = errno;
      syslog(LOG_ERR, "couldn't open /etc/shadow for appending : %m");
      goto BACK_OUT;
    }
    error = fprintf(fp,"%s\n",sentry);
    if (error < 0) {
      error_save = errno;
      syslog(LOG_ERR, "couldn't write to /etc/shadow : %m");
      goto BACK_OUT;
    }
    fclose(fp);
    error = 0;
  }; break;
  case modify:
  case delete: {
    fpr = fopen("/etc/opasswd_a", "r");
    if (fpr == (FILE *)0) {
      error_save = errno;
      syslog(LOG_ERR, "couldn't open /etc/opasswd_a for reading : %m");
      goto DONE_WPS;
    }
    fp = fopen("/etc/passwd","w");
    if (fp == (FILE *)0) {
      error_save = errno;
      syslog(LOG_ERR, "couldn't open /etc/passwd for writing : %m");
      goto BACK_OUT;
    }
    while (!feof(fpr)) {
      error = fscanf(fpr, "%[^\n]\n",buffer);
      if (error != 1) {
        error_save = errno;
	syslog(LOG_ERR, "couldn't read /etc/opasswd_a : %m");
	goto BACK_OUT;
      }
      if (!strncmp(login, buffer, login_len)) {
	if (buffer[login_len] == ':') { /* match made in heaven :) */
	  if (action == modify) {
	    error = fprintf(fp,"%s\n",pentry);
	    if (error < 0) {
              error_save = errno;
	      syslog(LOG_ERR, "couldn't write to /etc/passwd");
	      goto BACK_OUT;
	    }
	  } /* else remove which is no action */
	} else { /* didn't match need to print what was there */
	  error = fprintf(fp,"%s\n",buffer);
	  if (error < 0) {
            error_save = errno;
	    syslog(LOG_ERR, "couldn't write to /etc/passwd");
	    goto BACK_OUT;
	  }
	}
      } else {
	error = fprintf(fp,"%s\n",buffer);
	if (error < 0) {
          error_save = errno;
	  syslog(LOG_ERR, "couldn't write to /etc/passwd");
	  goto BACK_OUT;
	}
      }
    }
    fclose(fp);
    fclose(fpr);
    fpr = fopen("/etc/oshadow_a", "r");
    if (fpr == (FILE *)0) {
      error_save = errno;
      syslog(LOG_ERR, "couldn't open /etc/oshadow_a for reading : %m");
      goto BACK_OUT;
    }
    fp = fopen("/etc/shadow","w");
    if (fp == (FILE *)0) {
      error_save = errno;
      syslog(LOG_ERR, "couldn't open /etc/shadow for writing : %m");
      goto BACK_OUT;
    }
    while (!feof(fpr)) {
      error = fscanf(fpr, "%[^\n]\n",buffer);
      if (error != 1) {
        error_save = errno;
	syslog(LOG_ERR, "couldn't read /etc/oshadow_a : %m");
	goto BACK_OUT;
      }
      if (!strncmp(login, buffer, login_len)) {
	if (buffer[login_len] == ':') { /* match made in heaven :) */
	  if (action == modify) {
	    error = fprintf(fp,"%s\n",sentry);
	    if (error < 0) {
              error_save = errno;
	      syslog(LOG_ERR, "couldn't write to /etc/shadow");
	      goto BACK_OUT;
	    }
	  } /* else remove which is no action */
	} else { /* not a match write it out */
	  error = fprintf(fp, "%s\n",buffer);
	  if (error < 0) {
            error_save = errno;
	    syslog(LOG_ERR, "couldn't write to /etc/shadow");
	    goto BACK_OUT;
	  }
	}
      } else {
	error = fprintf(fp,"%s\n",buffer);
	if (error < 0) {
          error_save = errno;
	  syslog(LOG_ERR, "couldn't write to /etc/shadow");
	  goto BACK_OUT;
	}
      }
    }
  }; break;
  default: break;
  };
  error = 0;
DONE_WPS:
  if (fp != (FILE *)0) {
    fclose(fp);
  }
  if (fpr != (FILE *)0) {
    fclose(fpr);
  }
  ulckpwdf();
  errno = error_save;
  return error;
BACK_OUT:
  /* copy back passwd and shadow */
  error = _file_copy("/etc/opasswd_a", "/etc/passwd", 0644, 0444);
  if (error != 0) {
    syslog(LOG_CRIT, "WHOOP! WHOOP! couldn't back out passwd : %m");
  }
  error = _file_copy("/etc/oshadow_a", "/etc/shadow", 0600, 0400);
  if (error != 0) {
    syslog(LOG_CRIT, "WHOOP! WHOOP! couldn't back out shadow : %m");
  }
  ulckpwdf();
  errno = error_save;
  return(-1);
}

int
_setpwinfo (struct passwd *p_entry, int create) {
  char          pentry[BUFFER_SIZE];
  char          sentry[BUFFER_SIZE];
  struct passwd *pinfo;
  Action_t      action;

  action = modify;
  pinfo = getpwnam(p_entry->pw_name); 
  if (pinfo == (struct passwd *)0) {
    if (create == 0) {
      return 2;
    } else {
      action = add;
    }
  } else {
    if (pinfo->pw_uid == 0) {
      return 1;
    }
  }
  if (p_entry->pw_uid == 0) {
    return 1;
  }
  sprintf(pentry,"%s:%s:%d:%d:%s:%s:%s", p_entry->pw_name, "x",
	  p_entry->pw_uid, p_entry->pw_gid, p_entry->pw_gecos,
	  p_entry->pw_dir, p_entry->pw_shell);
  sprintf(sentry,"%s:%s:%ld::::::", p_entry->pw_name, p_entry->pw_passwd,
	  _n_days_epoch());
  return (_write_pass_shadow(action, p_entry->pw_name, pentry, sentry));
}

int
_rmpwnam (char *name) {
  struct passwd *pinfo;

  pinfo = getpwnam(name); 
  if (pinfo == (struct passwd *)0) {
      return 2;
  }
  if (pinfo->pw_uid == 0) {
    return 1;
  }
  return (_write_pass_shadow(delete, name, (char *)0, (char *)0));
}
