global agent:table[string] of int;

event http_header(c: connection, is_orig: bool, name: string, value: string)
	{
		if(!agent[value.user-agent])
		{
			agent[value.user-agent]=1;
		}
		eles
		{
			agent[value.user-agent]+=1;
			if(agent[value.user-agent]==3)
			{
				print c.sourceip+" is a proxy";
			}
		}
	}
