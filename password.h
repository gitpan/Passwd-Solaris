/*
 * password provides an non-interactive interface for
 * creating, deleting, and modifying password entries
 *
 * $Id: password.h,v 1.2 1999/01/23 07:10:03 eric Exp $
 */

#ifndef _Password_h_
#define _Password_h_

#include <pwd.h>

#define CREATE 1
#define NO_CREATE 0

/* 
   takes a password structure, will create if create is true and entry doesn't exist 
   this routine calls getpwnam so you cannot just use the struct passwd * that it
   returns as the information will be overwritten.
   returns 0 on success;
   returns -1 on system error, errno set to error
   returns 1 for user had uid 0
   returns 2 for user doesn't exist and create flag was set to NO_CREATE
*/
int _setpwinfo(struct passwd *password_entry, int create);

/* 
   removes password entry corresponding to the name given
   returns 0 on success
   returns -1 ons system error, errno set to error
   returns 1 for user had uid 0
   returns 2 for user doesn't exist
*/
int _rmpwnam(char *name); /* doesn't allow removal of uid 0 accounts */

#endif
