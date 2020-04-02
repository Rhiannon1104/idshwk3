global agent : table[addr,string] of int = table();
global rem : table[addr] of int = table();

event http_all_headers(c: connection, is_orig: bool, hlist: mime_header_list)
	{
		if([c$id$orig_h, to_lower( c$http$user_agent)] !in agent)
		{
			agent[c$id$orig_h, to_lower(c$http$user_agent)]=1;
		}
	}
	
event zeek_done()
	{
		for([j,i] in agent)
		{
			if(j !in rem)
			{
				rem[j]=1;
			}
			else 
			{
				rem[j]+=1;
			}
		}
		for(j in rem)
		{
			if( rem[j] >= 3 )
			{
				print fmt("%s is a proxy",j);
			}
		}
	}
