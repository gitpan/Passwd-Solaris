#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#ifdef __cplusplus
}
#endif

#include <shadow.h>
#include "password.h"

static int
not_here(s)
char *s;
{
    croak("%s not implemented on this architecture", s);
    return -1;
}

static double
constant(name, arg)
char *name;
int arg;
{
    errno = 0;
    switch (*name) {
    case 'A':
	break;
    case 'B':
	break;
    case 'C':
	break;
    case 'D':
	break;
    case 'E':
	break;
    case 'F':
	break;
    case 'G':
	break;
    case 'H':
	break;
    case 'I':
	break;
    case 'J':
	break;
    case 'K':
	break;
    case 'L':
	break;
    case 'M':
	break;
    case 'N':
	break;
    case 'O':
	break;
    case 'P':
	break;
    case 'Q':
	break;
    case 'R':
	break;
    case 'S':
	break;
    case 'T':
	break;
    case 'U':
	break;
    case 'V':
	break;
    case 'W':
	break;
    case 'X':
	break;
    case 'Y':
	break;
    case 'Z':
	break;
    }
    errno = EINVAL;
    return 0;

not_there:
    errno = ENOENT;
    return 0;
}


MODULE = Passwd::Solaris		PACKAGE = Passwd::Solaris		


double
constant(name,arg)
	char *		name
	int		arg


int
xs_setpwinfo(p_entry, create)
	SV *    p_entry
	int      create
	PREINIT:

		struct passwd my_pass;
		int           length;

	CODE:
	
		memset((void *)&my_pass, 0, sizeof(my_pass));
		my_pass.pw_name = SvPV(*(av_fetch((AV *)SvRV(p_entry), 0, 0)), length);
		my_pass.pw_passwd = SvPV(*(av_fetch((AV *)SvRV(p_entry), 1, 0)), length);
		my_pass.pw_uid = SvIV(*(av_fetch((AV *)SvRV(p_entry), 2, 0)));
		my_pass.pw_gid = SvIV(*(av_fetch((AV *)SvRV(p_entry), 3, 0)));
		my_pass.pw_gecos = SvPV(*(av_fetch((AV *)SvRV(p_entry), 4, 0)), length);
		my_pass.pw_dir = SvPV(*(av_fetch((AV *)SvRV(p_entry), 5, 0)), length);
		my_pass.pw_shell = SvPV(*(av_fetch((AV *)SvRV(p_entry), 6, 0)), length);
		RETVAL = _setpwinfo(&my_pass, create);

	OUTPUT:
	RETVAL

int
rmpwnam(name)
	char *	name

	CODE:
		RETVAL = _rmpwnam(name);
	OUTPUT:
	RETVAL

SV *
xs_getcrypted(name)
	char *  name
	PREINIT:
		
		SV*          tmp_sv;
		struct spwd  shadfo;
		struct spwd* shadptr;
		char         shadbuf[1024];
		
	CODE:

		memset((void *)&shadfo, 0, sizeof(shadfo));
		memset((void *)shadbuf, 0, 1024);
		shadptr = getspnam_r(name, &shadfo, shadbuf, 1023);
		if (shadptr != (struct spwd*)0) {
		  RETVAL = newSVpv(shadfo.sp_pwdp, strlen(shadfo.sp_pwdp));
		} else {
		  XSRETURN_UNDEF;
		}
	
	OUTPUT:
	RETVAL
		