#include"syscall_obj.h"
#include"sim.h"
#include<algorithm>

//setsockopt option names
#define OSF_SO_DEBUG		0x0001
#define OSF_SO_ACCEPTCONN	0x0002
#define OSF_SO_REUSEADDR	0x0004
#define OSF_SO_KEEPALIVE	0x0008
#define OSF_SO_DONTROUTE	0x0010
#define OSF_SO_BROADCAST	0x0020
#define OSF_SO_USELOOPBACK	0x0040
#define OSF_SO_LINGER		0x0080
#define OSF_SO_OOBINLINE	0x0100
#define OSF_SO_REUSEPORT	0x0200
#define OSF_SO_RESVPORT		0x100000	//This is probably handled incorrectly with SO_BINDTODEVICE
xlate_table_t new_sockopt_map()
{
	xlate_table_t retval;
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SO_DEBUG,SO_DEBUG));
#ifdef SO_ACCEPTCONN
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SO_ACCEPTCONN,SO_ACCEPTCONN));
#endif
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SO_REUSEADDR,SO_REUSEADDR));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SO_KEEPALIVE,SO_KEEPALIVE));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SO_DONTROUTE,SO_DONTROUTE));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SO_BROADCAST,SO_BROADCAST));
#ifdef SO_USELOOPBACK
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SO_USELOOPBACK,SO_USELOOPBACK));
#endif
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SO_LINGER,SO_LINGER));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SO_OOBINLINE,SO_OOBINLINE));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SO_RESVPORT,SO_BINDTODEVICE));
#ifdef SO_REUSEPORT
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SO_REUSEPORT,SO_REUSEPORT));
#endif
	return retval;
}

//setsockopt TCP options
#define OSF_TCP_NODELAY		0x01	//don't delay send to coalesce packets
#define OSF_TCP_MAXSEG		0x02	//maximum segment size
#define OSF_TCP_RPTR2RXT	0x03	//set repeat count for R2 RXT timer
#define OSF_TCP_KEEPIDLE	0x04	//secs before initial keepalive probe
#define OSF_TCP_KEEPINTVL	0x05	//seconds between keepalive probes
#define OSF_TCP_KEEPCNT		0x06	//num of keepalive probes before drop
#define OSF_TCP_KEEPINIT	0x07	//initial connect timeout (seconds)
#define OSF_TCP_PUSH		0x08	//set push bit in outbnd data packets
#define OSF_TCP_NODELACK	0x09	//don't delay send to coalesce packets
xlate_table_t new_tcpopt_map()
{
	xlate_table_t retval;
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_TCP_NODELAY,TCP_NODELAY));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_TCP_MAXSEG,TCP_MAXSEG));
#ifdef TCP_RPTR2RXT
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_TCP_RPTR2RXT,TCP_RPTR2RXT));
#endif
#ifdef TCP_KEEPIDLE
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_TCP_KEEPIDLE,TCP_KEEPIDLE));
#endif
#ifdef TCP_KEEPINTVL
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_TCP_KEEPINTVL,TCP_KEEPINTVL));
#endif
#ifdef TCP_KEEPCNT
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_TCP_KEEPCNT,TCP_KEEPCNT));
#endif
#ifdef TCP_KEEPINIT
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_TCP_KEEPINIT,TCP_KEEPINIT));
#endif
#ifdef TCP_PUSH
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_TCP_PUSH,TCP_PUSH));
#endif
#ifdef TCP_NODELACK
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_TCP_NODELACK,TCP_NODELACK));
#endif
	return retval;
}

//setsockopt IP options (netinet/in.h) -> (bits/in.h)
#define OSF_IP_TOS		0x03	//int; IP type of service and precedence
xlate_table_t new_ipopt_map()
{
	xlate_table_t retval;
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_IP_TOS,IP_TOS));
	return retval;
}

//setsockopt level names
#define OSF_SOL_SOCKET		0xffff		//options for socket level
#define OSF_SOL_IP		0		//dummy for IP
#define OSF_SOL_TCP		6		//tcp
#define OSF_SOL_UDP		17		//user datagram protocol
xlate_table_t new_socklevel_map()
{
	xlate_table_t retval;
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SOL_SOCKET,SOL_SOCKET));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SOL_IP,SOL_IP));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SOL_TCP,SOL_TCP));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SOL_UDP,SOL_UDP));
	return retval;
}

//socket() address families
#define OSF_AF_UNSPEC		0
#define OSF_AF_UNIX		1		//Unix domain sockets
#define OSF_AF_INET		2		//internet IP protocol
#define OSF_AF_IMPLINK		3		//arpanet imp addresses
#define OSF_AF_PUP		4		//pup protocols: e.g. BSP
#define OSF_AF_CHAOS		5		//mit CHAOS protocols
#define OSF_AF_NS		6		//XEROX NS protocols
#define OSF_AF_ISO		7		//ISO protocols
#define OSF_AF_ROUTE		17		//Internal Routing Protocol
#define OSF_AF_INET6		26		//IPv6: UDP, TCP, etc.
xlate_table_t new_family_map()
{
	xlate_table_t retval;
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_AF_UNSPEC,AF_UNSPEC));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_AF_UNIX,AF_UNIX));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_AF_INET,AF_INET));
#ifdef AF_IMPLINK
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_AF_IMPLINK,AF_IMPLINK));
#endif
#ifdef AF_PUP
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_AF_PUP,AF_PUP));
#endif
#ifdef CHAOS
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_AF_CHAOS,AF_CHAOS));
#endif
#ifdef AF_NS
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_AF_NS,AF_NS));
#endif
#ifdef AF_ISO
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_AF_ISO,AF_ISO));
#endif
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_AF_ROUTE,AF_ROUTE));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_AF_INET6,AF_INET6));
	return retval;
}

//socket() socket types
#define OSF_SOCK_STREAM		1		//stream (connection) socket
#define OSF_SOCK_DGRAM		2		//datagram (conn.less) socket
#define OSF_SOCK_RAW		3		//raw socket
#define OSF_SOCK_RDM		4		//reliably-delivered message
#define OSF_SOCK_SEQPACKET	5		//sequential packet socket
xlate_table_t new_socktype_map()
{
	xlate_table_t retval;
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SOCK_STREAM,SOCK_STREAM));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SOCK_DGRAM,SOCK_DGRAM));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SOCK_RAW,SOCK_RAW));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SOCK_RDM,SOCK_RDM));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_SOCK_SEQPACKET,SOCK_SEQPACKET));
	return retval;
}

//open(2) flags for Alpha/AXP OSF target, syscall.c automatically maps
//between these codes to/from host open(2) flags
#define OSF_O_RDONLY		0x0000
#define OSF_O_WRONLY		0x0001
#define OSF_O_RDWR		0x0002
#define OSF_O_NONBLOCK		0x0004
#define OSF_O_APPEND		0x0008
#define OSF_O_CREAT		0x0200
#define OSF_O_TRUNC		0x0400
#define OSF_O_EXCL		0x0800
#define OSF_O_NOCTTY		0x1000
#define OSF_O_SYNC		0x4000
xlate_table_t new_openflags_map()
{
	xlate_table_t retval;
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_O_RDONLY, O_RDONLY));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_O_WRONLY, O_WRONLY));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_O_RDWR, O_RDWR));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_O_APPEND, O_APPEND));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_O_CREAT, O_CREAT));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_O_TRUNC, O_TRUNC));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_O_EXCL, O_EXCL));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_O_NONBLOCK, O_NONBLOCK));
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_O_NOCTTY, O_NOCTTY));
#ifdef O_SYNC
	retval.data.push_back(std::make_pair((md_gpr_t)OSF_O_SYNC, O_SYNC));
#endif
	return retval;
}

//Since we have to acquire and fix the filename in various places, we should functionalize it
std::string get_filename(mem_t* mem, md_addr_t addr)
{
	std::string filename;
	mem->mem_strcpy(Read, addr, filename);

	//Currently, mem_strcpy copies the NULL character into the string. This ends up inserted into filename.
	//Remove a trailing NULL, if it exists
	if(*filename.rbegin() == 0)
	{
		filename.erase(filename.end()-1);
	}

#ifdef SLASH_FIX
	if((filename[0]=='/') && (filename[1]=='/'))
	{
		int start = 2;
		while(filename[start]=='/')
		{
			start++;
		}
		filename = filename.substr(start);
		//sys_output("Trying to fix bad path: %s \t",filename.c_str());
//		sys_output("(path fixed)");
	}
	while(filename.find("//")!=std::string::npos)
	{
		//sys_output("Trying to fix bad path: %s \t",filename.c_str());
		filename.replace(filename.find("//"),2,"/");
//		sys_output("(path fixed)");
	}
#endif

#ifdef ALPHA_LIB
#ifdef LINUX_LIB
	//This one doesn't really work....
	static std::string replace = "../sysfiles/linux-sys-root";
#else
//	static std::string replace = "../sysfiles/alpha-sys-root";
	static std::string replace = "/home/jloew/.nfs/Desktop/m-sim-c++/sysfiles/alpha-sys-root";
#endif
	//This is meant to redirect Tru64 OS files
	//	These have been required by Spec2K and Spec2K6 (non_shared versions)
	//	/usr/lib/nls/msg/C/libc.cat
	//	/usr/share/.msg_conv-C
	//	/etc/zoneinfo/localtime
	//	/etc/zoneinfo/GMT flags
	//	/etc/zoneinfo/posixrules
	//	/usr/lib/nls/msg/en_US.UTF-8/for_msg.cat
	//	/usr/share/.msg_conv-en_US.UTF-8
	//	/usr/lib/nls/msg/en_US.ISO8859-1/for_msg.cat
	//This now allows us to find shared object files and other relevant files
	if(filename[0] == '/')
	{
		if(filename.find("jloew")==std::string::npos)
		{
			filename = replace + filename;
		}
	}

	if((filename.substr(0,5)=="/usr/") || (filename.substr(0,5)=="/etc/") || (filename.substr(0,6)=="/sbin/") || (filename.substr(0,5)=="/lib/") || (filename.substr(0,5)=="/var/") || (filename.substr(0,5)=="/bin/"))
	{
		filename = replace + filename;
	}

	//This handles the problem with povray: SPEC-benchmark.tga
	if(filename.find("SPEC-benchmark.tga")!=std::string::npos)
	{
		filename = "./SPEC-benchmark.tga";
	}

//	if(filename == ".")
//	{
//		filename = replace + "/" + filename;
//	}

//	if(filename == "..")
//	{
//		filename = replace + "/" + filename;
//	}
#endif
	return filename;
}

int translate_signal(int in)
{
	switch(in)
	{
	case 7:		return 33;
	case 10:	return 7;
	case 12:	return 31;
	case 16:	return 23;
	case 17:	return 19;
	case 18:	return 20;
	case 19:	return 18;
	case 20:	return 17;
	case 23:	return 29;
	case 29:	return 30;
	case 30:	return 10;
	case 31:	return 12;
	default:	return in;
	}
}

unsigned long long translate_sigmask(unsigned long long in)
{
	unsigned long long retval = 0;
	for(int i=0;i<64;i++)
	{
		if(in & (1<<i))
		{
			retval |= translate_signal(i+1);
		}
	}
	return retval;
}

void osf_sigaction_action(int signum)
{
	//Hack: We don't really have a good way to figure out which process caused the signal
	//Or even, which one should respond to it.
	//We assume that the most recent context with a signal handler takes care of it.
	//If none exist, the most recent context with an ignore, takes care of it.
	//Otherwise, it should never get here.
	int sig_ign = -1;
	int sig_new = -1;
	for(int i=0;i<num_contexts;i++)
	{
		if(contexts[i].sigaction_array[signum])
		{
			if(contexts[i].sigaction_array[signum] == 1)
			{
				sig_ign = i;
			}
			else
			{
				sig_new = i;
			}
		}
	}
	if((sig_ign == -1) && (sig_new == -1))
	{
		//It may occur that a signal handler is placed and the process exits without giving it up.
		//And if it does give it up, that still may be a problem (since we only have one real process).
		fprintf(stderr,"Can't process signal %d, may have been smashed\n",signum);
	}
	else
	{
		//FIXME: This could very well be the wrong process.
		int context_id = sig_ign;
		if(sig_new != -1)
		{
			context_id = sig_new;
		}
		else
		{
			//ignore signal
			fprintf(stderr, " Ignored %d for context %d\t",signum,context_id);
			return;
		}

		fprintf(stderr," Caught %d for context %d\t",signum,context_id);
		contexts[context_id].pending_signal = signum;
	}
}
