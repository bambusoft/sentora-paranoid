#!/usr/bin/perl 

# Unofficial Sentora Postfix Policy Script
# =============================================
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#  OS VERSION supported: Ubuntu 14.04 32bit and 64bit
#
#  Official website: http://sentora-paranoid.open-source.tk
#
#  Modifed by Mario Ricardo Rodriguez Somohano, sentora-paranoid(at)open-source.tk
#  based on the original SMTP Policy Daemon script developed by 
#  Simone Caruso, http://www.simonecaruso.com/limit-sender-rate-in-postfix/
#
# Parameters: 

use Socket;
use POSIX ;
use DBI;
use Switch;
use threads;
use threads::shared;
use Thread::Semaphore; 
use File::Basename;
my $semaphore = new Thread::Semaphore;
#CONFIGURATION SECTION (this data must be taken from /etc/sentora/configs/sentora-paranoid/postfix/sp-policyd.conf)
my @allowedhosts = ('127.0.0.1', '%%LOCAL_IP%%');
my $LOGFILE = "/var/sentora/logs/sp-policyd.log";
my $port = 24;	# Private mail port
my $listen_address = '0.0.0.0';
my $s_key_type = 'email'; #domain or email
my $dsn = "DBI:mysql:sentora_postfix:127.0.0.1";
my $db_user = '%%DBUSER%%';
my $db_passwd = '%%DBPASS%%';
my $db_table = 'mailbox';
my $db_quotacol = 'msgquota';
my $db_tallycol = 'msgtally';
my $db_timecol = 'timestamp';
my $db_wherecol = 'username';
my $deltaconf = 'hourly'; #hourly, daily, weekly, monthly
my $sql_getquota = "SELECT $db_quotacol, $db_tallycol, $db_timecol FROM $db_table WHERE $db_wherecol = ? AND $db_quotacol > 0";
my $sql_updatequota = "UPDATE $db_table SET $db_tallycol = ?, $db_timecol = ? WHERE $db_wherecol = ?";
#my $sql_updatequota = "UPDATE $db_table SET $db_tallycol = $db_tallycol + ?, $db_timecol = ? WHERE $db_wherecol = ?";
#END OF CONFIGURATION SECTION
$0=join(' ',($0,@ARGV));

if($ARGV[0] eq "printshm"){
	my $out = `echo "printshm"|nc $listen_address $port`;
	print $out;
	exit(0);
}
my %quotahash :shared;
my %scoreboard :shared;
my $lock:shared;
my $cnt=0;
my $proto = getprotobyname('tcp');
my $thread_count = 3;
my $min_threads = 2;
# create a socket, make it reusable
socket(SERVER, PF_INET, SOCK_STREAM, $proto) or die "socket: $!";
setsockopt(SERVER, SOL_SOCKET, SO_REUSEADDR, 1) or die "setsock: $!";
my $paddr = sockaddr_in($port, inet_aton($listen_address)); #Server sockaddr_in
bind(SERVER, $paddr) or die "bind: $!";# bind to a port, then listen
listen(SERVER, SOMAXCONN) or die "listen: $!";
&daemonize;
$SIG{TERM} = \&sigterm_handler;
$SIG{HUP} = \&print_cache;

# #######################
# Main server entry point
# #######################
while (1) {	# Forever

	# Start processes 
	my $i = 0;
	my @threads;
	while($i < $thread_count){
		#$threads[$i] = threads->new(\&start_thr)->detach();
		threads->new(\&start_thr);
		logger("Started thread num $i.");
		$i++;
	}
	
	# Repetitive tasks
	while(1){
		sleep 5;
		$cnt++;
		my $r = 0;
		my $w = 0;
		# Commit results and flush cache every time_cycle
		if($cnt % 6 == 0){
			lock($lock);
			if (%quotahash) {
				#&print_cache;
				&commit_cache;
				&flush_cache;
				logger("Master: cache committed and flushed");
			}
		}
		
		#Mantain process balance
		while (my ($k, $v) = each(%scoreboard)){
			if($v eq 'running'){
				$r++;
			}else{
				$w++;
			}
		}
		if($r/($r + $w) > 0.9){
			threads->new(\&start_thr);
			logger("New thread started");
		}
		
		# Show stats
		if($cnt % 150 == 0){
			logger("STATS: threads running: $r, threads waiting $w.");
		}
	}
}

exit;

# ####################
# sp-policy subprocess
# ####################
sub start_thr {
	my $threadid = threads->tid();
	my $client_addr;
	my $client_ipnum;
	my $client_ip;
	my $client;
	while(1){
		$scoreboard{$threadid} = 'waiting';
		$semaphore->down();#TODO move to non-block
		$client_addr = accept($client, SERVER);
		$semaphore->up();
		$scoreboard{$threadid} = 'running';
		if(!$client_addr){
			#logger("TID: $threadid accept() failed with: $!");	# Why did this throws a lot of messages at end of subprocess?
			next;
		}	
		my ($client_port, $client_ip) = unpack_sockaddr_in($client_addr);
		$client_ipnum = inet_ntoa($client_ip);
		logger("TID: $threadid accepted from $client_ipnum ...");
		
		select($client);
		$|=1;

		# is this IP allowed? then process, else disconnect
		if(grep $_ eq $client_ipnum, @allowedhosts){
			#my $client_host = gethostbyaddr($client_ip, AF_INET);
			#if (! defined ($client_host)) { $client_host=$client_ipnum;}
			my $message;
			my @buf;
			while(!eof($client)) {
				$message = <$client>;
				if($message =~ m/printshm/){	##### msg: printshm
					my $r=0;
					my $w =0;
					print $client "Printing shm:\r\n";
					print $client "Domain\t\t:\tQuota\t:\tUsed\t:\tExpire\r\n";
					while(($k,$v) = each(%quotahash)){
						chomp(my $exp = ctime($quotahash{$k}{'expire'}));
						print $client "$k\t:\t".$quotahash{$k}{'quota'}."\t:\t $quotahash{$k}{'tally'}\t:\t$exp\r\n";
					}
					while (my ($k, $v) = each(%scoreboard)){
						if($v eq 'running'){
							$r++;
						}else{
							$w++;
						}
					}
					print $client "Threads running: $r, Threads waiting: $w\r\n";
					last;
				}elsif($message =~ m/=/){		##### msg: =
					push(@buf, $message);
					next;
				}elsif($message == "\r\n"){		##### msg: CR+LF
					logger("Handle new request with: $threadid");
					my $ret = &handle_req(@buf);
					logger("Finished request by: $threadid");
					if($ret =~ m/unknown/){
						last;
					#New thread model - old code
					#	shutdown($client,2);
					#??	threads->exit(0);
					}else{
						print $client "action=$ret\n\n";
					}
					@buf = ();
				}else{									##### msg: not understood
					print $client "message not understood\r\n";
				}
			}
		}else{
			logger("Client $client_ipnum connection not allowed.");
		}
		shutdown($client,2);
		undef $client;
		logger("TID: $threadid Client $client_ipnum disconnected.");
	}
	undef $scoreboard{$threadid};
	threads->exit(0);
}

# ####################
# handle client request
# ####################
sub handle_req {
	my @buf = @_;
	my $protocol_state;
	my $sasl_username; 
	my $recipient_count;
	local $/ = "\n";
	
	# Get postfix sended parameters
	foreach $aline(@buf){
		my @line = split("=", $aline);
		chomp(@line);
		#logger("Line ". $line[0] ."=". $line[1]);
		switch($line[0]){
			case "protocol_state" { 
				chomp($protocol_state = $line[1]);
			}
			case "sasl_username"{
				chomp($sasl_username = $line[1]);
			}
			case "recipient_count"{
				chomp($recipient_count = $line[1]);
			}
		}
	}

	# Mail does not contains DATA section or identified user, lets postfix handle it
	if($protocol_state !~ m/DATA/ || $sasl_username eq "" ){
		return "ok";
	}
	
	# Get current domain/email
	my $skey = '';
	if($s_key_type eq 'domain'){
		$skey = (split("@", $sasl_username))[1];
	}else{
		$skey = $sasl_username;
	}	
	
	# Get email data from db or cache
	if ( !exists($quotahash{$skey}) || !exists($quotahash{$skey}{'quota'}) ){	# if this domain/email is not in the cache then search in DB
		lock($lock);
		my $dbh = DBI->connect($dsn, $db_user, $db_passwd);
		my $sql_query = $dbh->prepare($sql_getquota);
		$sql_query->execute($skey);
		if($sql_query->rows > 0){	# if domain/email in database then load it
			while(@row = $sql_query->fetchrow_array()){
				$quotahash{$skey} = &share({});
				$quotahash{$skey}{'quota'} = $row[0];
				$quotahash{$skey}{'tally'} = $row[1];
				if($row[2]){		# if has expiration in DB take it or generate new expiration
					$quotahash{$skey}{'expire'} = $row[2];
				}else{
					$quotahash{$skey}{'expire'} = calcexpire($deltaconf);
					#$quotahash{$skey}{'expire'} = 0;
				}
				undef @row;
			}
			chomp(my $exp = ctime($quotahash{$skey}{'expire'}));
			logger("Cached: $skey $quotahash{$skey}{'tally'}/$quotahash{$skey}{'quota'} exp=[$exp]");
			$dbh->disconnect;
		}else{
			$dbh->disconnect;
			return "dunno";
		}
	}

	# Reached expiration time, the reset tally/sum and store it
	if ($quotahash{$skey}{'expire'} < time()){
		#$quotahash{$skey} = &share({});
		$quotahash{$skey}{'tally'} = 0;
		$quotahash{$skey}{'expire'} = calcexpire($deltaconf);
		logger("Reset: $skey $quotahash{$skey}{'tally'}/$quotahash{$skey}{'quota'} exp=[$quotahash{$skey}{'expire'}]");
	}

	# Exeeded quota
	$result=$quotahash{$skey}{'tally'} + $recipient_count;
	if ( $result > $quotahash{$skey}{'quota'} ){
		logger("Reject: $skey $quotahash{$skey}{'tally'}/$quotahash{$skey}{'quota'}");
		return "471 $deltaconf message quota exceeded"; 
	}
	$quotahash{$skey}{'tally'} = $result;

	return "dunno";
}

sub sigterm_handler {
	shutdown(SERVER,2);
	lock($lock);
	logger("SIGTERM received.\nFlushing cache...\nExiting.");
	&commit_cache;
	exit(0);
}

# ####################
# commit cache to DB
# ####################
sub commit_cache {
	my $dbh = DBI->connect($dsn, $db_user, $db_passwd);
	if ($dbh) {
		#lock($lock); -- lock at upper level
		while(($k,$v) = each(%quotahash)){
			my $sql_query = $dbh->prepare($sql_updatequota);
			$sql_query->execute($quotahash{$k}{'tally'}, $quotahash{$k}{'expire'}, $k) or logger("Query error:".$sql_query->errstr);
			chomp(my $exp = ctime($quotahash{$k}{'expire'}));
			logger("stored $k: $quotahash{$k}{'tally'}/$quotahash{$k}{'quota'} exp=$exp");
		}
		$dbh->disconnect;
	}
}

# ####################
# clean cache (flush)
# ####################
sub flush_cache {
	lock($lock);
	foreach $k(keys %quotahash){
		delete $quotahash{$k};
	}
}

# ####################
# show cache
# ####################
sub print_cache {
	lock($lock);
	foreach $k(keys %quotahash){
		chomp(my $exp = ctime($quotahash{$k}{'expire'}));
		logger("$k: $quotahash{$k}{'tally'}/$quotahash{$k}{'quota'} exp=[$exp]");
	}
}

# ####################
# act as a server
# ####################
sub daemonize {
	my ($i,$pid);
	my $mask = umask 0027;
	print "sentora-paranoid SMTP Policy Daemon.\n Limiting $s_key_type/$deltaconf\n Logging to $LOGFILE\n";
	#Should i delete this??
	#$ENV{PATH}="/bin:/usr/bin";
	#chdir("/");
	close STDIN;
	if(!defined(my $pid=fork())){
		die "Impossible to fork\n";
	}elsif($pid >0){
		exit 0;
	}
	setsid();
	close STDOUT;
	open STDIN, "/dev/null";
	open LOG, ">>$LOGFILE" or die "Unable to open $LOGFILE: $!\n";
	select((select(LOG), $|=1)[0]);
	open STDERR, ">>$LOGFILE" or die "Unable to redirect STDERR to STDOUT: $!\n";
	open PID, ">/var/run/".basename($0).".pid" or die $!;
	print PID $$."\n";
	close PID;
	umask $mask;
}

# ####################
# return new time limit based on $deltaconf
# ####################
sub calcexpire{
        my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
        my ($arg) = @_;
        if($arg eq 'monthly'){
                $exp = mktime (0, 0, 0, 1, ++$mon, $year);
        }elsif($arg eq 'weekly'){
                $exp = mktime (0, 0, 0, 1, $mon, $year);
        }elsif($arg eq 'daily'){
                $exp = mktime (0, 0, 0, ++$mday, $mon, $year);
        }elsif($arg eq 'hourly'){
                $exp = mktime (0, $min, ++$hour, $mday, $mon, $year);
        }else{
                $exp = mktime (0, 0, 0, 1, ++$mon, $year);
        }
        return $exp;
}

# ####################
# Log activity
# ####################
sub logger {
	my ($arg) = @_;
	my $time = localtime();
	chomp($time);
	flock(LOG, LOCK_EX);
	print LOG  "$time $arg\n";
	flock(LOG, LOCK_UN);
}
