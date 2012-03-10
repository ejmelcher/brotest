@load ./extract

module FileAnalysis;

export {
	redef enum Action += { ACTION_VIRUS_TOTAL };
	redef action_dependencies += { [ACTION_VIRUS_TOTAL] = set(ACTION_EXTRACT) };
	
	redef record Info += {
		## The percentage of the Virus Total scanners that indicated this was a bad file.
		vt_pct:    count &optional;
	};
	
}

event FileAnalysis::got_data(f: Info, data: string)
	{
	if ( ACTION_VIRUS_TOTAL !in f$actions )
		return;
	
	
	}
