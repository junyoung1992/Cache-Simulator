#ifndef SYSCALL_OBJ_H
#define SYSCALL_OBJ_H

#define ALPHA_LIB
//#define LINUX_LIB
#define SLASH_FIX

#ifdef TPM_THREAD
#include <pthread.h>
#include <sys/wait.h>
#endif

#ifdef SYS_DEBUG
#include <iostream>
#include <iomanip>
#endif

#include "host.h"
#include "misc.h"
#include "machine.h"
#include "memory.h"
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/types.h>
#include <string>
#include <cerrno>
#include <ctime>
#include <signal.h>
#include <sys/stat.h>
#include <climits>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/times.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <termios.h>
#include <sys/mount.h>
#include <rpcsvc/rex.h>
#include <sys/socket.h>
#include <sys/poll.h>

#if defined(linux)
#include <utime.h>
#include <dirent.h>
#include <sys/vfs.h>
#include <sgtty.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#endif

#if !defined(linux) && !defined(sparc) && !defined(hpux) && !defined(__hpux) && !defined(ultrix)
#include <sys/select.h>
#endif

/*
#if defined(sparc) && defined(__unix__)
//dorks
#undef NL0
#undef NL1
#undef CR0
#undef CR1
#undef CR2
#undef CR3
#undef TAB0
#undef TAB1
#undef TAB2
#undef XTABS
#undef BS0
#undef BS1
#undef FF0
#undef FF1
#undef ECHO
#undef NOFLSH
#undef TOSTOP
#undef FLUSHO
#undef PENDIN
#endif
*/

#if defined(hpux) || defined(__hpux)
#undef CR0
#endif

#ifdef __FreeBSD__
#include <sys/ioctl_compat.h>
#else
#include <termio.h>
#endif

/*#if defined(hpux) || defined(__hpux)
//et tu, dorks!
#undef HUPCL
#undef ECHO
#undef B50
#undef B75
#undef B110
#undef B134
#undef B150
#undef B200
#undef B300
#undef B600
#undef B1200
#undef B1800
#undef B2400
#undef B4800
#undef B9600
#undef B19200
#undef B38400
#undef NL0
#undef NL1
#undef CR0
#undef CR1
#undef CR2
#undef CR3
#undef TAB0
#undef TAB1
#undef BS0
#undef BS1
#undef FF0
#undef FF1
#undef EXTA
#undef EXTB
#undef B900
#undef B3600
#undef B7200
#undef XTABS
#include <sgtty.h>
#include <utime.h>
#endif*/

//Forward Declarations are provided first so you know what is in this file.
class vm_stack;
class osf_cpu_info;
class osf_flock;
class xlate_table_t;
class osf_winsize;
class osf_termios;
class osf_ifconf;
class osf_statbuf;
class osf_statbuf64;
class osf_sgttyb;
class osf_sigstack;
class osf_sigaction;
class osf_sigcontext;
class osf_statfs;
class osf_statfs64;
class osf_timeval;
class osf_timezone;
class osf_rusage;
class osf_rlimit;
class osf_sockaddr;
class osf_iovec;
class osf_dirent;
class osf_tbl_sysfile;
class osf_tbl_procinfo;
class osf_utsname;

//internal system call buffer size, used primarily for file name arguments,
//argument larger than this will be truncated
#define MAXBUFSIZE 		1024

//total bytes to copy from a valid pointer argument for ioctl() calls,
//syscall.c does not decode ioctl() calls to determine the size of the
//arguments that reside in memory, instead, the ioctl() proxy simply copies
//NUM_IOCTL_BYTES bytes from the pointer argument to host memory
#define NUM_IOCTL_BYTES		128

//setsockopt level names
#define OSF_SOL_SOCKET		0xffff		//options for socket level
#define OSF_SOL_IP		0		//dummy for IP
#define OSF_SOL_TCP		6		//tcp
#define OSF_SOL_UDP		17		//user datagram protocol

//Since we have to acquire and fix the filename in various places, we should functionalize it
std::string get_filename(mem_t* mem, md_addr_t addr);

class vm_stack
{
	public:
		md_addr_t		address;		//address hint
		md_gpr_t		rsize;			//red zone size
		md_gpr_t		ysize;			//yellow zone size
		md_gpr_t		gsize;			//green zone size
		md_gpr_t		swap;			//amount of swap to reserve
		md_gpr_t		incr;			//growth increment
		unsigned long long	align;			//address alignment
		md_gpr_t		flags;			//MAP_FIXED etc.
		md_addr_t		attr;			//allocation policy (address to type malloc_attr)
		md_gpr_t		reserved;
};

class osf_cpu_info
{
	public:
		int current_cpu, cpus_in_box, cpu_type, ncpus;
		unsigned long long cpus_present, cpus_running, cpu_binding, cpu_ex_binding;
		int mhz, unused[3];
};


class osf_flock
{
	public:
		short l_type;			//Type of lock: F_RDLCK, F_WRLCK, or F_UNLCK.
		short l_whence;			//Where `l_start' is relative to (like `lseek').
		unsigned long long l_start;	//Offset where the lock begins.
		unsigned long long l_len;	//Size of the locked area; zero means until EOF.
		pid_t l_pid;			//Process holding the lock.
		struct flock copy_out()
		{
			struct flock retval;
			retval.l_type = l_type;
			retval.l_whence = l_whence;

			//These may be 64 or 32 bit targets
			retval.l_start = l_start;
			retval.l_len = l_len;

			retval.l_pid = l_pid;
			return retval;
		}
};

//translate system call arguments
class xlate_table_t
{
	public:
//		md_gpr_t target_val;
//		int host_val;
		std::vector<std::pair<md_gpr_t, int> > data;
		int translate(md_gpr_t target_val, const char * name)
		{
			for(size_t i=0;i<data.size();i++)
			{
				if(target_val == data[i].first)
				{
					return data[i].second;
				}
			}

			//not found, issue warning and return target_val
			warn("Could not translate argument for `%s': %d", name, target_val);
			return target_val;
		}

		int convert(md_gpr_t source_val)
		{
			int retval = 0;
			for(size_t i=0;i<data.size();i++)
			{
				if(source_val & data[i].first)
				{
					retval |= data[i].second;
				}
			}
			return retval;
		}
};

xlate_table_t new_sockopt_map();
xlate_table_t new_tcpopt_map();
xlate_table_t new_ipopt_map();
xlate_table_t new_socklevel_map();
xlate_table_t new_family_map();
xlate_table_t new_socktype_map();
xlate_table_t new_openflags_map();

class osf_winsize
{
	public:
		osf_winsize()
		: ws_row(0), ws_col(0), ws_xpixel(0), ws_ypixel(0)
		{}
		unsigned short	ws_row;			//rows, in characters
		unsigned short	ws_col;			//columns, in characters
		unsigned short	ws_xpixel;		//horizontal size, pixels
		unsigned short	ws_ypixel;		//vertical size, pixels
};

class osf_termios
{
	public:
		unsigned int	c_iflag;	//input flags
		unsigned int	c_oflag;	//output flags
		unsigned int	c_cflag;	//control flags
		unsigned int	c_lflag;	//local flags
		unsigned char	c_cc[20];	//control chars
		int		c_ispeed;	//input speed
		int		c_ospeed;	//output speed

		termios copy_out()
		{
			termios retval;
			retval.c_cflag = (c_cflag >> 4);

			retval.c_iflag = c_iflag & 0x29ff;
			if(c_iflag & 0x200)
			{
				retval.c_iflag |= 0x400;
			}
			if(c_iflag & 0x400)
			{
				retval.c_iflag |= 0x1000;
			}
			if(c_iflag & 0x1000)
			{
				retval.c_iflag |= 0x200;
			}

			retval.c_oflag = c_oflag & 0x1f9;
			if(c_oflag & 0x2)
			{
				retval.c_oflag |= 0x4;
			}
			if(c_oflag & 0x4)
			{
				retval.c_oflag |= 0x2;
			}
			if(c_oflag & 0x300)	//This may be wrong
			{
				retval.c_oflag |= 0x100;
			}
			if(c_oflag & 0x400)
			{
				retval.c_oflag |= 0x800;
			}
			if(c_oflag & 0x800)
			{
				retval.c_oflag |= 0x1000;
			}
			if(c_oflag & 0x1000)
			{
				retval.c_oflag |= 0x200;
			}
			if(c_oflag & 0x2000)
			{
				retval.c_oflag |= 0x400;
			}
			if(c_oflag & 0x4000)
			{
				retval.c_oflag |= 0x8000;
			}
			if(c_oflag & 0x8000)
			{
				retval.c_oflag |= 0x2000;
			}
			if(c_oflag & 0x10000)
			{
				retval.c_oflag |= 0x4000;
			}
//			if(c_oflag & 0x40000)		//Uncomment if XTABS is equivalent to OXTABS
//			{
//				retval.c_oflag |= 0x1800;
//			}

			retval.c_lflag = c_lflag & 0x8;
			if(c_lflag & 0x1)
			{
				retval.c_lflag |= 0x800;
			}
			if(c_lflag & 0x2)
			{
				retval.c_lflag |= 0x10;
			}
			if(c_lflag & 0x4)
			{
				retval.c_lflag |= 0x20;
			}
			if(c_lflag & 0x10)
			{
				retval.c_lflag |= 0x40;
			}
			if(c_lflag & 0x20)
			{
				retval.c_lflag |= 0x400;
			}
			if(c_lflag & 0x40)
			{
				retval.c_lflag |= 0x200;
			}
			if(c_lflag & 0x80)
			{
				retval.c_lflag |= 0x1;
			}
			if(c_lflag & 0x100)
			{
				retval.c_lflag |= 0x2;
			}
			if(c_lflag & 0x400)
			{
				retval.c_lflag |= 0x8000;
			}
			if(c_lflag & 0x4000)
			{
				retval.c_lflag |= 0x4;
			}
			if(c_lflag & 0x400000)
			{
				retval.c_lflag |= 0x100;
			}
			if(c_lflag & 0x800000)
			{
				retval.c_lflag |= 0x1000;
			}
			if(c_lflag & 0x20000000)
			{
				retval.c_lflag |= 0x4000;
			}
			if(c_lflag & 0x80000000)
			{
				retval.c_lflag |= 0x80;
			}

			memset(retval.c_cc,255,32);
			retval.c_cc[VINTR] = c_cc[8];
			retval.c_cc[VQUIT] = c_cc[9];
			retval.c_cc[VERASE] = c_cc[3];
			retval.c_cc[VKILL] = c_cc[5];
			retval.c_cc[VEOF] = c_cc[0];
			retval.c_cc[VTIME] = c_cc[17];
			retval.c_cc[VMIN] = c_cc[16];
			retval.c_cc[VSWTC] = 255;
			retval.c_cc[VSTART] = c_cc[12];
			retval.c_cc[VSTOP] = c_cc[13];
			retval.c_cc[VSUSP] = c_cc[10];
			retval.c_cc[VEOL] = c_cc[1];
			retval.c_cc[VREPRINT] = c_cc[6];
			retval.c_cc[VDISCARD] = c_cc[15];
			retval.c_cc[VWERASE] = c_cc[4];
			retval.c_cc[VLNEXT] = c_cc[14];
			retval.c_cc[VEOL2] = c_cc[2];
			retval.c_ispeed = c_ispeed;
			retval.c_ospeed = c_ospeed;
			return retval;
		}

		void copy_in(termios & in)
		{
			c_cflag = (in.c_cflag << 4) & ~0xff;

			c_iflag = in.c_iflag & 0x29ff;
			if(in.c_iflag & 0x200)
			{
				c_iflag |= 0x1000;
			}
			if(in.c_iflag & 0x400)
			{
				c_iflag |= 0x200;
			}
			if(in.c_iflag & 0x1000)
			{
				c_iflag |= 0x400;
			}
			//IUTF8 is lost

			c_oflag = in.c_oflag & 0x1f9;
			if(in.c_oflag & 0x2)
			{
				c_oflag |= 0x4;
			}
			if(in.c_oflag & 0x4)
			{
				c_oflag |= 0x2;
			}
			if(in.c_oflag & 0x100)	//This may be wrong
			{
				c_oflag |= 0x300;
			}
			if(in.c_oflag & 0x200)
			{
				c_oflag |= 0x1000;
			}
			if(in.c_oflag & 0x400)
			{
				c_oflag |= 0x2000;
			}
			if(in.c_oflag & 0x800)
			{
				c_oflag |= 0x400;
			}
			if(in.c_oflag & 0x1000)
			{
				c_oflag |= 0x800;
			}
			if(in.c_oflag & 0x2000)
			{
				c_oflag |= 0x8000;
			}
			if(in.c_oflag & 0x4000)
			{
				c_oflag |= 0x10000;
			}
			if(in.c_oflag & 0x8000)
			{
				c_oflag |= 0x4000;
			}
//			if(in.c_oflag & 0x1800)		//Uncomment if XTABS is equivalent to OXTABS
//			{
//				c_oflag |= 0x40000;
//			}

			c_lflag = in.c_lflag & 0x8;
			if(in.c_lflag & 0x1)
			{
				c_lflag |= 0x80;
			}
			if(in.c_lflag & 0x2)
			{
				c_lflag |= 0x100;
			}
			if(in.c_lflag & 0x4)
			{
				c_lflag |= 0x4000;
			}
			if(in.c_lflag & 0x10)
			{
				c_lflag |= 0x2;
			}
			if(in.c_lflag & 0x20)
			{
				c_lflag |= 0x4;
			}
			if(in.c_lflag & 0x40)
			{
				c_lflag |= 0x10;
			}
			if(in.c_lflag & 0x80)
			{
				c_lflag |= 0x80000000;
			}
			if(in.c_lflag & 0x100)
			{
				c_lflag |= 0x400000;
			}
			if(in.c_lflag & 0x200)
			{
				c_lflag |= 0x40;
			}
			if(in.c_lflag & 0x400)
			{
				c_lflag |= 0x20;
			}
			if(in.c_lflag & 0x800)
			{
				c_lflag |= 0x1;
			}
			if(in.c_lflag & 0x1000)
			{
				c_lflag |= 0x800000;
			}
			if(in.c_lflag & 0x4000)
			{
				c_lflag |= 0x20000000;
			}
			if(in.c_lflag & 0x8000)
			{
				c_lflag |= 0x400;
			}

			memset(c_cc,255,20);
			c_cc[0] = in.c_cc[VEOF];
			c_cc[1] = in.c_cc[VEOL];
			c_cc[2] = in.c_cc[VEOL2];
			c_cc[3] = in.c_cc[VERASE];
			c_cc[4] = in.c_cc[VWERASE];
			c_cc[5] = in.c_cc[VKILL];
			c_cc[6] = in.c_cc[VREPRINT];
			c_cc[7] = 255;	//spare
			c_cc[8] = in.c_cc[VINTR];
			c_cc[9] = in.c_cc[VQUIT];
			c_cc[11] = 255;	//VDSUSP
			c_cc[12] = in.c_cc[VSTART];
			c_cc[10] = in.c_cc[VSUSP];
			c_cc[13] = in.c_cc[VSTOP];
			c_cc[14] = in.c_cc[VLNEXT];
			c_cc[15] = in.c_cc[VDISCARD];
			c_cc[16] = in.c_cc[VMIN];
			c_cc[17] = in.c_cc[VTIME];
			c_cc[18] = 255;	//VSTATUS
			c_cc[19] = 255;	//spare
			c_ispeed = in.c_ispeed;
			c_ospeed = in.c_ospeed;
		}
};


//ifconf structure for alpha
class osf_ifconf
{
	public:
		int ifc_len;
		int padding;
		union
		{
			md_gpr_t ifcu_buf;
			md_gpr_t ifcu_req;

		} ifc_ifcu;
};

//target stat() buffer definition, the host stat buffer format is automatically mapped to/from this format in syscall.c
class osf_statbuf
{
	public:
		osf_statbuf()
		: st_dev(0), st_ino(0), st_mode(0), st_nlink(0), pad0(0), st_uid(0), st_gid(0),
			st_rdev(0), pad1(0), st_size(0), osf_st_atime(0), st_spare1(0), osf_st_mtime(0),
			st_spare2(0), osf_st_ctime(0), st_spare3(0), st_blksize(0), st_flags(0), st_gen(0)
		{}

		void copy_in(class stat & sbuf)
		{
			st_dev = MD_SWAPW(sbuf.st_dev);
			st_mode = MD_SWAPW(sbuf.st_mode);
			st_nlink = sbuf.st_nlink;
			st_rdev = MD_SWAPW(sbuf.st_rdev);
			st_size = MD_SWAPQ(sbuf.st_size);

			st_uid = MD_SWAPW(sbuf.st_uid);
			st_gid = MD_SWAPW(sbuf.st_gid);

			st_ino = MD_SWAPW(sbuf.st_ino);
			osf_st_atime = MD_SWAPW(sbuf.st_atime);
			osf_st_mtime = MD_SWAPW(sbuf.st_mtime);
			osf_st_ctime = MD_SWAPW(sbuf.st_ctime);
			st_blksize = MD_SWAPQ(sbuf.st_blksize);
			st_blocks = MD_SWAPQ(sbuf.st_blocks);
			st_flags = 0;
			st_gen = 0;
		}

		void output(std::ostream & out)
		{
			out << std::hex << "st_dev(" << st_dev << ") st_ino(" << st_ino << ") st_rdev(" << st_rdev << ") st_size(" << st_size << ") st_mode(" << st_mode;
			out << ") st_uid(" << st_uid << ") st_gid(" << st_gid << ") st_n_link(" << st_nlink << ") st_atime(" << osf_st_atime;
			out << ") st_mtime(" << osf_st_mtime << ") st_ctime(" << osf_st_ctime << ") st_blksize(" << st_blksize << ") st_blocks(" << st_blocks << ")" << std::dec << std::endl;
		}

		word_t st_dev;
		word_t st_ino;
		word_t st_mode;
		half_t st_nlink;
		half_t pad0;			//to match Alpha/AXP padding...
		word_t st_uid;
		word_t st_gid;
		word_t st_rdev;
		word_t pad1;			//to match Alpha/AXP padding...
		qword_t st_size;
		word_t osf_st_atime;
		word_t st_spare1;
		word_t osf_st_mtime;
		word_t st_spare2;
		word_t osf_st_ctime;
		word_t st_spare3;
		word_t st_blksize;
		word_t st_blocks;
		word_t st_flags;
		word_t st_gen;
};

class osf_statbuf64
{
	public:
		osf_statbuf64()
		: st_dev(0), st_retired1(0), st_mode(0), st_nlink(0), st_nlink_reserved(0), st_uid(0), st_gid(0),
			st_rdev(0), st_ldev(0), st_size(0), st_retired2(0), st_uatime(0), st_retired3(0),
			st_umtime(0), st_retired4(0), st_uctime(0), st_retired5(0), st_retired6(0), st_flags(0),
			st_gen(0), st_ino(0), st_ino_reserved(0), osf_st_atime(0), st_atime_reserved(0), osf_st_mtime(0),
			st_mtime_reserved(9), osf_st_ctime(0), st_ctime_reserved(0), st_blksize(0), st_blocks(0)
		{
			for(size_t i=0;i<4;i++)
			{
				st_spare[i] = 0;
			}
		}

		void copy_in(class stat64 & sbuf)
		{
			//On Tru64, the reserved areas usually have values equivalent to the non-64 bit version, should we replicate here?
			st_dev = MD_SWAPW(sbuf.st_dev);
			st_mode = MD_SWAPW(sbuf.st_mode);
			st_nlink = sbuf.st_nlink;
			st_rdev = MD_SWAPW(sbuf.st_rdev);
			st_size = MD_SWAPQ(sbuf.st_size);

			st_uid = MD_SWAPW(sbuf.st_uid);
			st_gid = MD_SWAPW(sbuf.st_gid);

			st_ino = sbuf.st_ino;
			osf_st_atime = MD_SWAPW(sbuf.st_atime);
			osf_st_mtime = MD_SWAPW(sbuf.st_mtime);
			osf_st_ctime = MD_SWAPW(sbuf.st_ctime);
			st_blksize = MD_SWAPQ(sbuf.st_blksize);
			st_blocks = MD_SWAPQ(sbuf.st_blocks);
			st_retired1 = st_retired2 = st_retired3 = st_retired4 = st_retired5 = st_retired6 = 0;
			st_nlink_reserved = 0;
			st_ldev = 0;
			st_uatime = st_umtime = st_uctime = 0;
			st_flags = 0;
			st_gen = 0;
			st_ino_reserved = st_atime_reserved = st_mtime_reserved = st_ctime_reserved = 0;
			st_spare[0] = st_spare[1] = st_spare[2] = st_spare[3] = 0;
		}

		void output(std::ostream & out)
		{
			out << std::hex << "st_dev(" << st_dev << ") st_ino(" << st_ino << ") st_rdev(" << st_rdev << ") st_size(" << st_size << ") st_mode(" << st_mode;
			out << ") st_uid(" << st_uid << ") st_gid(" << st_gid << ") st_n_link(" << st_nlink << ") st_atime(" << osf_st_atime;
			out << ") st_mtime(" << osf_st_mtime << ") st_ctime(" << osf_st_ctime << ") st_blksize(" << st_blksize << ") st_blocks(" << st_blocks << ")" << std::dec << std::endl;
		}

		word_t			st_dev;
		word_t			st_retired1;
		word_t			st_mode;
		half_t			st_nlink;
		half_t			st_nlink_reserved;
		unsigned int		st_uid;
		unsigned int		st_gid;
		word_t			st_rdev;
		word_t			st_ldev;
		qword_t			st_size;

		word_t			st_retired2;
		word_t			st_uatime;
		word_t			st_retired3;
		word_t			st_umtime;
		word_t			st_retired4;
		word_t			st_uctime;

		word_t			st_retired5;
		word_t			st_retired6;

		unsigned int		st_flags;
		unsigned int		st_gen;

		long long		st_spare[4];

		word_t			st_ino;
		word_t			st_ino_reserved;

		word_t			osf_st_atime;
		word_t			st_atime_reserved;
		word_t			osf_st_mtime;
		word_t			st_mtime_reserved;
		word_t			osf_st_ctime;
		word_t			st_ctime_reserved;

		qword_t			st_blksize;
		qword_t			st_blocks;
};


//FIXME: This needs to be verified, it used to be byte_t for the first four and that
//didn't do assignment correctly
//short, short, char, char seems not to crash but byte_t.... is what the patch used
class osf_sgttyb
{
	public:
		osf_sgttyb()
		: sg_ispeed(0), sg_ospeed(0), sg_erase(0), sg_kill(0), sg_flags()
		{}
		byte_t sg_ispeed;	//input speed
		byte_t sg_ospeed;	//output speed
		byte_t sg_erase;	//erase character
		byte_t sg_kill;		//kill character
		shalf_t sg_flags;	//mode flags

		sgttyb copy_out()
		{
			sgttyb retval;
			retval.four = 4;
			retval.chars[0] = sg_ispeed;
			retval.chars[1] = sg_ospeed;
			retval.chars[2] = sg_erase;
			retval.chars[3] = sg_kill;
			retval.flags = sg_flags;
			return retval;
		}

		void copy_in(sgttyb & in)
		{
			sg_ispeed = in.chars[0];
			sg_ospeed = in.chars[1];
			sg_erase = in.chars[2];
			sg_kill = in.chars[3];
			sg_flags = in.flags;
		}
};

//Translate signals from alpha to linux
int translate_signal(int in);
unsigned long long translate_sigmask(unsigned long long in);

void osf_sigaction_action(int signum);

class osf_sigaction
{
	public:
		osf_sigaction()
		: ptr(NULL), sa_mask(0), sa_flags(0)//, sa_signo(0)
		{}

		void output(std::ostream & out)
		{
			out << std::hex << ptr << " mask(" << sa_mask << std::dec << ") flags(" << sa_flags << ")"; //") signo(" << sa_signo << ")" << std::endl;
		}

		void * ptr;
		unsigned long long sa_mask;
		int sa_flags; //sa_signo;
};

class osf_sigstack
{
	public:
		osf_sigstack()
		: ss_sp(NULL), ss_onstack(0)
		{}
		void * ss_sp;
		int ss_onstack;
};

class osf_sigcontext
{
	public:
		osf_sigcontext()
		: sc_onstack(0), sc_mask(0), sc_pc(0), sc_ps(0),
			sc_ownedfp(0),sc_fpcr(0), sc_fp_control(0)
		{
			for(size_t i=0;i<32;i++)
			{
				sc_regs[i] = sc_fpregs[i] = 0;
			}
		}
		sqword_t	sc_onstack;		//sigstack state to restore
		sqword_t	sc_mask;		//signal mask to restore
		sqword_t	sc_pc;			//pc at time of signal
		sqword_t	sc_ps;			//psl to retore
		qword_t		sc_regs[32];		//processor regs 0 to 31
		sqword_t	sc_ownedfp;		//fp has been used
		qword_t		sc_fpregs[32];		//fp regs 0 to 31
		qword_t		sc_fpcr;		//floating point control register
		qword_t		sc_fp_control;		//software fpcr
		sqword_t	sc_reserved1;
		int		sc_kreserved1;
		int		sc_kreserved2;
		qword_t		sc_ssize;		//stack size
		qword_t		sc_sbase;		//stack base
		qword_t		sc_traparg_a0;
		qword_t		sc_traparg_a1;
		qword_t		sc_traparg_a2;
		qword_t		sc_fp_trap_pc;
		qword_t		sc_fp_trigger_sum;
		qword_t		sc_fp_trigger_inst;
};

class osf_statfs
{
	public:
		osf_statfs()
		: f_type(0), f_flags(0), f_fsize(0), f_bsize(0), f_blocks(0), f_bfree(0), f_bavail(0), f_files(0), f_ffree(0), f_fsid(0),
			f_namemax(0), f_reserved1(0)
		{
			size_t i = 0;
			for(;i<8;i++)
			{
				f_spare[i] = f_mntonname[i] = f_mntfromname[i] = mount_info[i] = 0;
			}
			for(;i<80;i++)
			{
				f_mntonname[i] = f_mntfromname[i] = mount_info[i] = 0;
			}
			for(;i<90;i++)
			{
				f_mntonname[i] = f_mntfromname[i] = 0;
			}
		}
		shalf_t		f_type;			//type of filesystem (see below)
		shalf_t		f_flags;		//copy of mount flags
		word_t		f_fsize;		//fundamental filesystem block size
		word_t		f_bsize;		//optimal transfer block size
		word_t		f_blocks;		//total data blocks in file system, may not represent fs size.

		word_t		f_bfree;		//free blocks in fs
		word_t		f_bavail;		//free blocks avail to non-root
		word_t		f_files;		//total file nodes in file system
		word_t		f_ffree;		//free file nodes in fs
		qword_t		f_fsid;			//file system id
		half_t		f_namemax;		//Maximum filename length (statvfs)
		shalf_t		f_reserved1;		//spare or grow f_namemax later
		word_t		f_spare[8];
		char		f_mntonname[90];	//Directory on which mounted
		char		f_mntfromname[90];	//Mounted filesystem
		char		mount_info[80];		//Mount options (this should be union mount_info mount_info, see sys/mount.h - this is a stub for now)
};


class osf_statfs64
{
	public:
		osf_statfs64()
		: f_type(0), f_flags(0), f_fsid(0), f_namemax(0), f_reserved1(0), f_flags2(0), f_fsize(0), f_bsize(0), f_blocks(0), f_bfree(0), f_bavail(0),
			f_files(0), f_ffree(0)
		{
			size_t i = 0;
			for(;i<7;i++)
			{
				f_mntonname[i] = f_mntfromname[i] = f_retired[i] = f_spare2[i] = f_spare[i] = f_retired8[i] = f_retired9[i] = mount_info[i] = 0;
			}
			for(;i<8;i++)
			{
				f_mntonname[i] = f_mntfromname[i] = f_spare2[i] = f_spare[i] = f_retired8[i] = f_retired9[i] = mount_info[i] = 0;
			}
			for(;i<14;i++)
			{
				f_mntonname[i] = f_mntfromname[i] = f_spare2[i] = f_retired8[i] = f_retired9[i] = mount_info[i] = 0;
			}
			for(;i<80;i++)
			{
				f_mntonname[i] = f_mntfromname[i] = f_retired8[i] = f_retired9[i] = mount_info[i] = 0;
			}
			for(;i<90;i++)
			{
				f_mntonname[i] = f_mntfromname[i] = f_retired8[i] = f_retired9[i] = 0;
			}
			for(;i<1024;i++)
			{
				f_mntonname[i] = f_mntfromname[i] = 0;
			}
		}
		shalf_t		f_type;			//type of filesystem (see below)
		shalf_t		f_flags;		//copy of mount flags
		word_t		f_retired[7];		//These are f_retired1, f_retired2 .. f_retired7 in the source
		qword_t		f_fsid;			//file system id
		half_t		f_namemax;		//Maximum filename length (statvfs)
		shalf_t		f_reserved1;		//spare or grow f_namemax later
		word_t		f_spare[8];
		char		f_retired8[90];
		char		f_retired9[90];
		char		mount_info[80];		//Mount options (this should be union mount_info mount_info, see sys/mount.h - this is a stub for now)
		qword_t		f_flags2;		//Extended f_flags field
		long long	f_spare2[14];
		qword_t		f_fsize;		//fundamental filesystem block size
		qword_t		f_bsize;		//optimal transfer block size
		qword_t		f_blocks;		//total data blocks in file system, may not represent fs size.
		qword_t		f_bfree;		//free blocks in fs
		qword_t		f_bavail;		//free blocks avail to non-root
		qword_t		f_files;		//total file nodes in file system
		qword_t		f_ffree;		//free file nodes in fs
		char		f_mntonname[1024];
		char		f_mntfromname[1024];
};

class osf_timeval
{
	public:
		osf_timeval()
		: osf_tv_sec(0), osf_tv_usec(0)
		{}
		sword_t osf_tv_sec;	//seconds
		sword_t osf_tv_usec;	//microseconds
};

class osf_timezone
{
	public:
		osf_timezone()
		: osf_tz_minuteswest(0), osf_tz_dsttime(0)
		{}
		sword_t osf_tz_minuteswest;	//minutes west of Greenwich
		sword_t osf_tz_dsttime;		//type of dst correction
};

//target getrusage() buffer definition, the host stat buffer format is
//automagically mapped to/from this format in syscall.c
class osf_rusage
{
	public:
		osf_rusage()
		: osf_ru_maxrss(0), osf_ru_ixrss(0), osf_ru_idrss(0), osf_ru_isrss(0), osf_ru_minflt(0), osf_ru_majflt(0), osf_ru_nswap(0),
			osf_ru_inblock(0), osf_ru_oublock(0), osf_ru_msgsnd(0), osf_ru_msgrcv(0), osf_ru_nsignals(0), osf_ru_nvcsw(0), osf_ru_nivcsw(0)
		{}
		osf_timeval osf_ru_utime;
		osf_timeval osf_ru_stime;
		sword_t osf_ru_maxrss;
		sword_t osf_ru_ixrss;
		sword_t osf_ru_idrss;
		sword_t osf_ru_isrss;
		sword_t osf_ru_minflt;
		sword_t osf_ru_majflt;
		sword_t osf_ru_nswap;
		sword_t osf_ru_inblock;
		sword_t osf_ru_oublock;
		sword_t osf_ru_msgsnd;
		sword_t osf_ru_msgrcv;
		sword_t osf_ru_nsignals;
		sword_t osf_ru_nvcsw;
		sword_t osf_ru_nivcsw;
};

class osf_rlimit
{
	public:
		osf_rlimit()
		: osf_rlim_cur(0), osf_rlim_max(0)
		{}
		qword_t osf_rlim_cur;		//current (soft) limit
		qword_t osf_rlim_max;		//maximum value for rlim_cur
};

class osf_sockaddr
{
	public:
		osf_sockaddr()
		: sa_family(0)
		{
			for(size_t i=0;i<14;i++)
			{
				sa_data[i] = 0;
			}
		}
		half_t sa_family;		//address family, AF_xxx
		byte_t sa_data[14];		//14 bytes of protocol address
};

class osf_iovec
{
	public:
		osf_iovec()
		: iov_base(0), iov_len(0), pad(0)
		{}
		md_addr_t iov_base;		//starting address
		word_t iov_len;			//length in bytes
		word_t pad;
};

class osf_dirent
{
	public:
		osf_dirent()
		: d_ino(0), d_reclen(0), d_namlen(0)
		{
			for(size_t i=0;i<256;i++)
			{
				d_name[i] = 0;
			}
		}
		word_t d_ino;			//file number of entry
		half_t d_reclen;		//length of this record
		half_t d_namlen;		//length of string in d_name
		char d_name[256];		//DUMMY NAME LENGTH, the real maximum length is
						//returned by pathconf(). At this time, this MUST
						//be 256 -- the kernel requires it
};

class osf_tbl_sysinfo
{
	public:
		osf_tbl_sysinfo()
		: si_user(0), si_nice(0), si_sys(0), si_idle(0), si_hz(0), si_phz(0), si_boottime(0), wait(0)
		{}
		long si_user;		//user time
		long si_nice;		//nice time
		long si_sys;		//system time
		long si_idle;		//idle time
		long si_hz;
		long si_phz;
		long si_boottime;	//boot time in seconds
		long wait;		//wait time
};

#define OSF_PI_COMLEN		19	//length of command string
class osf_tbl_procinfo
{
	public:
		osf_tbl_procinfo()
		: pi_uid(0), pi_pid(0), pi_ppid(0), pi_pgrp(0), pi_ttyd(0), pi_status(0), pi_flag(0), pi_ruid(0), pi_svuid(0), pi_rgid(0),
			pi_svgid(0), pi_session(0), pi_tpgrp(0), pi_tsession(0), pi_jobc(0), pi_cursig(0), pi_sig(0), pi_sigmask(0),
			pi_sigignore(0), pi_sigcatch(0)
		{
			for(size_t i=0;i<=OSF_PI_COMLEN;i++)
			{
				pi_comm[i] = 0;
			}
		}
		uid_t		pi_uid;		//(effective) user ID
		pid_t		pi_pid;		//proc ID
		pid_t		pi_ppid;	//parent proc ID
		pid_t		pi_pgrp;	//proc group ID
		uid_t		pi_ttyd;	//controlling terminal number (dev_t is too large natively, use uid_t instead)
		int		pi_status;	//process status:
#define OSF_PI_EMPTY		0			//no process
#define OSF_PI_ACTIVE		1			//active process
#define OSF_PI_EXITING		2			//exiting
#define OSF_PI_ZOMBIE		3			//zombie
		int		pi_flag;	//other random flags
		char		pi_comm[OSF_PI_COMLEN+1];
						//short command name
		uid_t		pi_ruid;	//(real) user ID
		uid_t		pi_svuid;	//saved (effective) user ID
		gid_t		pi_rgid;	//(real) group ID
		gid_t		pi_svgid;	//saved (effective) group ID
		pid_t		pi_session;	//session ID
		pid_t		pi_tpgrp;	//tty pgrp
		pid_t		pi_tsession;	//tty session id
		u_int		pi_jobc;	//# procs qualifying pgrp for job control
		int		pi_cursig;
		//the following are sigset_t (which is "quad" on alpha). Doesn't match well at all on linux
		qword_t		pi_sig;		//signals pending
		qword_t		pi_sigmask;	//current signal mask
		qword_t		pi_sigignore;	//signals being ignored
		qword_t		pi_sigcatch;	//signals being caught by user
};

class osf_utsname
{
	public:
//		osf_utsname()
//		{
//			for(size_t i=0;i<32;i++)
//			{
//				sysname[i] = nodename[i] = release[i] = version[i] = machine[i] = 0;
//			}
//		}
		char sysname[32];
		char nodename[32];
		char release[32];
		char version[32];
		char machine[32];
};

#endif
