require "fileinto";
	if exists "X-Spam-Flag" {
		  if header :contains "X-Spam-Flag" "NO" {
		  } else {
			  fileinto "Spam";
			  stop;
		  }
	}

	if header :contains "X-Spam-Level" "**********" {
		discard;
		stop;
	}

require "regex";
	if  header :regex	["subject"] [".*SPAM.*"]) {
		fileinto "Spam";
		stop;
	}
	
	if  header :regex	["subject"] [".*BULK.*"]) {
		fileinto "Spam";
		stop;
	}