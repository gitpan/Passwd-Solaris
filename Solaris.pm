package Passwd::Solaris;

use strict;
use Carp;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK $AUTOLOAD);

require Exporter;
require DynaLoader;
require AutoLoader;

@ISA = qw(Exporter DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@EXPORT = qw();
@EXPORT_OK = qw(
		modpwinfo
		setpwinfo
		rmpwnam
		mgetpwnam
		);

$VERSION = '0.65';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.

    my $constname;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "& not defined" if $constname eq 'constant';
    my $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($! =~ /Invalid/) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
		croak "Your vendor has not defined Passwd::Solaris macro $constname";
	}
    }
    *$AUTOLOAD = sub () { $val };
    goto &$AUTOLOAD;
}

bootstrap Passwd::Solaris $VERSION;

# Preloaded methods go here.
sub modpwinfo {
    my @info = @_;

    if (scalar(@info) != 7) {
	croak "modpwinfo: (name, crypted_pass, uid, gid, gecos, home, shell)";
    }
    return xs_setpwinfo(\@info, 0);
}

sub setpwinfo {
    my @info = @_;
    if (scalar(@info) != 7) {
	croak "setpwinfo: (name, crypted_pass, uid, gid, gecos, home, shell)";
    }
    return xs_setpwinfo(\@info, 1);
}

sub mgetpwnam {
    my ($login) = @_;
    my (@info, $crypted);
  
    undef @info;
    @info = getpwnam($login);
    if (defined(@info)) {
	undef $crypted;
	$crypted = xs_getcrypted($login);
	if (defined($crypted)) {
	    $info[1] = $crypted;
	}
        @info = @info[0..3,6..8];
    } else {
        return;
    }
    return @info;
}
    
# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

Passwd::Solaris - Perl module for manipulating the passwd and shadow files

=head1 SYNOPSIS

  use Passwd::Solaris qw(modpwinfo setpwinfo rmpwnam mgetpwnam);

  $err = modpwinfo(@info);
  $err = setpwinfo(@info);
  $err = rmpwnam($name);
  @info = mgetpwnam($name);

=head1 DESCRIPTION

Passwd::Solaris provides additional password routines.  It augments the getpw* functions with setpwinfo, modpwinfo, rmpwnam, mgetpwnam.  You need to run most of the functions as root or as someone who has permission to modify the shadow file.

setpwinfo and modpwinfo are called with arrays containing (in order):
 name, crypted_password, uid, gid, gecos, home_directory, shell

rmpwnam is called with a scalar containing the login name

mgetpwnam returns the same array that getpwnam returns without the 'unused' age or comment fields it also returns the crypted password if run with root permissions.

setpwinfo does a create/modify of the user.
modpwinfo only does a modify, it will return an error if the user doesn't exist.

rmpwnam removes the user with the given login from both the password and shadow files.  It returns an error if the user doesn't exist.

This module does call syslog in the C portion, but it doesn't call openlog.  If you wish to see the error output of the syslog you must do an openlog in your perl script.

You must be running as root in order to use this module. If it successfully completes an operation and you are not root then you have a huge security problem on your box.

This module as distributed does not allow operations to occur on uid 0 files

Return values:
  < 0	system error occurred, error value should be in $!
    0   no error
    1   operation attempt on uid 0
    2   user does not exist

=head1 Exported functions on the OK basis

  modpwinfo
  setpwinfo
  rmpwnam
  mgetpwnam

=head1 AUTHOR

Eric Estabrooks,  eric@urbanrage.com

=head1 SEE ALSO

perl(1).

=cut
