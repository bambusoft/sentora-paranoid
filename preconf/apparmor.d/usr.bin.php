# Author: Mario Rodriguez < sentora-paranoid (at) open-source.tk >

#include <tunables/global>

/usr/bin/php flags=(complain) {
	/etc/php5/** r,
	/etc/alternatives/** r,
	/etc/apache2/** r,
	/usr/bin/** r,
	/usr/include/php5/** r,
	/usr/lib/** r,
	/usr/sbin/php* r,
	/usr/share/** mr,
	/usr/X11R6/lib/** r,
	/var/cache/** r,
	/var/lib/** r,
	# php5 session mmap socket
	/var/lib/php5/session_mm_* rwlk,
	# file based session handler
	/var/lib/php5/sess_* rwlk,

	/etc/sentora/** rw,
	/var/sentora/** rw,

	/tmp/** wk,
}
