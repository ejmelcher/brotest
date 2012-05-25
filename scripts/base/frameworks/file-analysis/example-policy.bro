# This file is intended to be deleted eventually.

redef FileAnalysis::policy += {	
	[$trigger = FileAnalysis::IDENTIFIED_MIME,
	 $pred(rec: FileAnalysis::Info) = { return rec$mime_type == "application/pdf" || (rec$protocol == "SMTP" && rec$mime_type == /^image.*/); },
	 $action = FileAnalysis::ACTION_EXTRACT ],
	
	#[$trigger = FileAnalysis::IDENTIFIED_MIME,
	# $pred(rec: FileAnalysis::Info) = { return rec$mime_type == "application/x-dosexec"; },
	# $action = VirusTotal::ACTION_HASH_MATCH ],
	
	#[$trigger = FileAnalysis::IDENTIFIED_BOF,
	# $pred(rec: FileAnalysis::Info) = {
	#	 return rec$protocol == "HTTP" && /facebook\.com$/ in rec$http$host;
	# },
	# $action = FileAnalysis::ACTION_BUFFER_BEGINNING],
	
	#[$trigger = FileAnalysis::IDENTIFIED_MIME,
	# $pred(rec: FileAnalysis::Info) = { return rec$mime_type == "application/x-dosexec"; },
	# $actions = set(FileAnalysis::ACTION_HASH_SHA256, FileAnalysis::ACTION_HASH_MD5, FileAnalysis::ACTION_HASH_SHA1) ],
	#
	[$trigger = FileAnalysis::IDENTIFIED_MIME,
	 $pred(rec: FileAnalysis::Info) = { return rec$mime_type == "application/x-dosexec"; },
	 $action = FileAnalysis::ACTION_MHR_CHECK],
	
	#[$trigger=FileAnalysis::IDENTIFIED_MIME,
	# $pred(rec: FileAnalysis::Info) = { return rec$meta_data["mime_type"] == "application/x-dosexec"; },
	# $action = FileAnalysis::ACTION_ANALYZER ],
};

# IGNORE THIS STUFF FOR NOW...

#event Files::found_dosexec(data: Files::DOSExec)
#	{
#	if ( data$compiled_at > network_time() - 48hrs )
#		{
#		print "holy crap this is probably bad!";
#		}
#	}


#redef FileAnalysis::policy += {
#	[$trigger=FileAnalysis::IDENTIFIED_MIME,
#	 $pred(rec: FileAnalysis::Info) = { return rec?$mime_type && rec$mime_type == "application/x-dosexec"; },
#	 $action = FileAnalysis::ACTION_VIRUS_TOTAL ],
#};
#