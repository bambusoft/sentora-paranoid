require "fileinto, regex";
	if exists "X-Spam-Flag" {
		  if header :contains "X-Spam-Flag" "NO" {
		  } else {
			  fileinto "Junk";
			  stop;
		  }
	}

	if header :contains "X-Spam-Level" "**********" {
		discard;
		stop;
	}

	if  header :regex	"subject" ".*SPAM.*" {
		fileinto "Junk";
		stop;
	}
	
	if  header :regex	"subject" ".*BULK.*" {
		fileinto "Junk";
		stop;
	}
