global agent:table[addr,string] of int = table();
global rem : table[addr] of int=table();

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
	{
		if([c$http$id$orig_h,to_lower(c$http$user_agent)] !in agent)
		{
			agent[c$http$id$orig_h,to_lower(c$http$user_agent)]=1;
		}
	}
	
event zeek_done()
	{
		for([i,j] in agent)
		{
			if(i !in rem)
			{
				rem[i]=1;
			}
			else 
			{
				rem[i]+=1;
			}
		}
		for([i,j] in agent)
		{
			if( rem[i] >= 3 )
			{
				print fmt("%s is a proxy",i);
			}
		}
	}
