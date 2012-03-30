# This file is intended to be deleted eventually.

redef FileAnalysis::policy += {
	#[$trigger=FileAnalysis::IDENTIFIED_NEW_FILE,
	# $action = FileAnalysis::ACTION_SNIFF_MIME ],
	
	#[$trigger = FileAnalysis::IDENTIFIED_NEW_FILE,
	# $action = FileAnalysis::ACTION_EXTRACT ],
	
	#[$trigger = FileAnalysis::IDENTIFIED_MIME,
	# $pred(rec: FileAnalysis::Info) = { return rec$mime_type == "application/x-dosexec"; },
	# $action = VirusTotal::ACTION_HASH_MATCH ],
	
	[$trigger = FileAnalysis::IDENTIFIED_MIME,
	 $pred(rec: FileAnalysis::Info) = { return rec$mime_type == "application/x-dosexec"; },
	 $action = FileAnalysis::ACTION_HASH_MD5 ],
	#
	[$trigger = FileAnalysis::IDENTIFIED_MD5,
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
#event FileAnalysis::virus_total_result(fid: string, results: set[VirusTotalResult])
#	{
#	for ( r in results )
#		{
#		if ( r$matched )
#			print r$scanner;
#		}
#	}