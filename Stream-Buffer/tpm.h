#ifdef TPM_THREAD

#define TPM_DEBUG

//Uncomment if the timing file has a representative data set of timings
//In the current code, TPM_SAMPLE_SIZE samples, sorted with an appropriate standard deviation
//#define TPM_PROBABILITY
//#define TPM_SAMPLE_SIZE		1000

#include<sys/times.h>
#include<vector>
#include<fstream>
#include<ctime>
#include<algorithm>
#define OSF_SYS_api_call		1024
#define TPM_BUFFER_SIZE			1024
#define TPM_RESPONSE_BUFFER		20000
#define TEST_SPEED			2794000000

//TPM sorting methods
#define TPM_FIFO			0
#define TPM_SRT				1

#define TPM_DATA_NAME			"timings.data_"

#define TPM_PORT			"TPM_PORT=6543"
#define TPM_SERVER_PORT			"TPM_SERVER_PORT=6543"
#define TPM_PATH			"TPM_PATH=/home/msimuser/"
#define TPM_SERVER			"TPM_SERVER_NAME=localhost"

//Timing Code
typedef union
{
	unsigned long long	int64;
	struct
	{
		unsigned int	lo, hi;
	} int32;
} cycle_counter;

#define RDTSC(cpu_c)					\
asm volatile( "rdtsc\n\t"				\
"movl %%eax, %0\n\t"					\
"movl %%edx, %1\n\t"					\
: "=r" ((cpu_c).int32.lo), "=r" ((cpu_c).int32.hi)	\
: : "%eax", "%edx")
//End of Timing Code

#ifdef TPM_DEBUG
void tpm_output(const char * format, ...)
{
	va_list v;
	va_start(v, format);
	char buf[TPM_BUFFER_SIZE];
	int size = vsprintf(buf,format,v);
	if(size>=TPM_BUFFER_SIZE)
	{
		std::cerr << "sys_output may have buffer overflowed (size: " << size << " avail: " << TPM_BUFFER_SIZE << ")" << std::endl;
		assert(size<TPM_BUFFER_SIZE);
	}
	std::cerr << buf;
	va_end(v);
}
#else
inline void tpm_output(const char * ignore, ...)
{}
#endif

//For ordering TPM calls (execution of), see "operator <"
class job_t
{
	public:
		job_t(int id, unsigned long long start, unsigned long long length, int tpm = -1)
		: context_id(id), start(start), length(length), tpm(tpm)
		{}
		int context_id;
		unsigned long long start, length;
		int tpm;

		bool operator < (const job_t & rhs) const
		{
			if(length == rhs.length)
			{
				if(start == rhs.start)
				{
					return context_id < rhs.context_id;
				}
				return start < rhs.start;
			}
			return length < rhs.length;
		}
};

//TPM module for ordering TPM calls (see syscall.c).
//Instantiated as:	tpm_module(ALGORITHM, NUMBER_OF_CORES);
class tpm_module
{
	public:
		tpm_module(int algo = 0, int count = 1)
		: my_algo(algo), times(count,0), last_times(count,0)
		{}
		void resize(size_t newsize)
		{
			times.resize(newsize,0);
			last_times.resize(newsize,0);
		}
		unsigned long long delay(unsigned long long now, unsigned long long time_needed, int id)
		{
			//Ensure times are not before now
			for(size_t i=0;i<times.size();i++)
			{
				times[i] = std::max(times[i], now);
			}

			unsigned long long retval = 0;
			switch(my_algo)
			{
			case TPM_FIFO:
				{
					int index = -1;
					unsigned long long soonest = (unsigned long long)-1;
					for(size_t i=0;i<times.size();i++)
					{
						if((times[i] < soonest) && ((contexts[id].alloc_tpm == -1) || (contexts[id].alloc_tpm == (int)i)))
						{
							soonest = times[i];
							index = i;
						}
					}
					assert(index != -1);
					retval = soonest + time_needed - now;
					last_times[index] = times[index];
					times[index] += time_needed;
					assert((contexts[id].alloc_tpm == -1) || (contexts[id].alloc_tpm == index));
					contexts[id].alloc_tpm = index;
				}
				break;
			case TPM_SRT:	//Shortest Remaining Time
					//Can not interrupt existing processes
				{
//					printf("@@@Starting SRT (%lld - %d)@@@\n",now, id);
					//Remove any jobs that have completed (that were queued)
					for(size_t i=0;i<jobs.size();i++)
					{
//						printf("\t*Pending Job %ld (%d) scheduled to start at %lld with length %lld on tpm %d\n", i, jobs[i].context_id, jobs[i].start, jobs[i].length, jobs[i].tpm);
					}

					//If there are pending jobs, schedule all of them
					for(size_t i=0, j=0;(i<jobs.size()) && (j<times.size());)
					{
						//If the thread is bound to a TPM and not this TPM, go to next TPM (possibly next job)
						if((contexts[jobs[i].context_id].alloc_tpm != -1) && ((size_t)contexts[jobs[i].context_id].alloc_tpm != j))
						{
							j++;
							if(j == times.size())
							{
								j = 0;
								i++;
							}
							continue;
						}

						if(times[j] <= now)
						{
							//TPM was free - make sure to use begin time from the job itself.
							times[j] = jobs[i].start + jobs[i].length;
//							fprintf(stderr,"Job finished %d\n",jobs[i].context_id);
							assert((contexts[jobs[i].context_id].alloc_tpm == -1) || ((size_t)contexts[jobs[i].context_id].alloc_tpm == j));
							contexts[jobs[i].context_id].alloc_tpm = j;
//							printf("\tJob %ld (%d) finished scheduled to start at %lld with length %lld on tpm %ld\n", i, jobs[i].context_id, jobs[i].start, jobs[i].length, j);
							jobs.erase(jobs.begin() + i);
							i--;
							j = 0;

						}
						else
						{
							//TPM not free, try next
							j++;
						}

						//We tried to schedule to all TPMs, can't do it. Move to next job.
						if(j == times.size())
						{
							j = 0;
							i++;
						}
					}

					//Then, get the soonest available TPM
					size_t index = 0;
					unsigned long long soonest = times[0];
					for(size_t i=1;i<times.size();i++)
					{
						if(times[i] < soonest)
						{
							soonest = times[i];
							index = i;
						}
					}

					//We have a free TPM, just schedule it
					if(soonest <= now)
					{
						retval = soonest + time_needed;
						if(now >= retval)
						{
							retval = 0;
						}
						else
						{
							retval -= now;
						}
						times[index] += time_needed;
//						fprintf(stderr,"Job from %d\n",id);
//						printf("***(%d) Current time %lld, soonest available for task %lld is at %lld(%ld) finish at %lld\n", id, now, time_needed, soonest, index, now+time_needed);
						break;
					}

					//We don't have a free TPM, sort the current jobs by length
					job_t this_job(id,0,time_needed,-1);
					jobs.push_back(this_job);
					std::sort(jobs.begin(), jobs.end());

					//Provide delays to all jobs (this will update those jobs)
					std::vector<unsigned long long> temptimes(times);
					size_t t_index = 0;
					for(size_t i=0;i<jobs.size();i++)
					{
						jobs[i].start = temptimes[t_index];
						temptimes[t_index] += jobs[i].length;
						jobs[i].tpm = t_index;
						contexts[jobs[i].context_id].tpm_delay = jobs[i].start + jobs[i].length;
						if(now >= contexts[jobs[i].context_id].tpm_delay)
						{
							contexts[jobs[i].context_id].tpm_delay = 0;
						}
						else
						{
							contexts[jobs[i].context_id].tpm_delay -= now;
						}
//						printf("\tJob %ld (%d) scheduled to start at %lld with length %lld on tpm %d\n", i, jobs[i].context_id, jobs[i].start, jobs[i].length, jobs[i].tpm);
						t_index = (t_index + 1) % temptimes.size();
					}
					retval = contexts[id].tpm_delay;
				}
				break;
			}
			return retval;
		}
		int my_algo;
		std::vector<unsigned long long> times;
		std::vector<unsigned long long> last_times;
		std::vector<job_t> jobs;
//		std::vector<int> context_id;
//		std::vector<unsigned long long *> targets;
};

//Timing data, this is global to the tpm file (it shouldn't be but can be changed later).
std::vector<double> timings;

cycle_counter start_time, end_time;
long long tpm_time()
{
//	For testing, we don't use the real time anymore anyway.
//	RDTSC(end_time);
//	return (long long)(end_time.int64 - start_time.int64) * TEST_SPEED;

#ifdef TPM_PROBABILITY
	double interval = timings[rand() % TPM_SAMPLE_SIZE];
	return (long long)(interval * TEST_SPEED);
#else
//	Convert timings to cycles based on TEST_SPEED
	double interval = timings[0];
	return (long long)(interval * TEST_SPEED);
#endif
}

//Get Seconds of "Real Time" (this is affected by simulator and other overheads)
long double tpm_ref_time()
{
	long long cur = end_time.int64 - start_time.int64;
	return (long double)cur / (long double)TEST_SPEED;
}

//This is the data structure passed by M-Sim to the tpm_handler (syscall.c)
class tpm_pass
{
	public:
	tpm_pass(md_gpr_t call_val, md_addr_t retloc, md_addr_t params, mem_t * mem, regs_t * regs)
	: call_val(call_val), retloc(retloc), params(params), mem(mem), regs(regs)
	{}
	md_gpr_t	call_val;
	md_addr_t	retloc, params;
	mem_t *		mem;
	regs_t *	regs;
};


void * tpm_handler(void * data)
{
//	tpm_output("In tpm handler\n");

	//Extract parameters passed from M-Sim (syscall.c)
	tpm_pass * passed = (tpm_pass *)data;
	md_gpr_t call_num = passed->call_val;
	md_addr_t retloc = passed->retloc;
	md_addr_t params = passed->params;
	mem_t * mem = passed->mem;
	regs_t * regs = passed->regs;

	//Acquire Timing Data
	timings.clear();
#ifdef TPM_PROBABILITY
	int read_count = TPM_SAMPLE_SIZE;
#else
	int read_count = 1;
#endif
	char call_num_buf[10];
	sprintf(call_num_buf,"%lld",call_num);
	std::ifstream infile((std::string(TPM_DATA_NAME) + call_num_buf).c_str());
	timings.resize(read_count);
	for(int i=0;i<read_count;i++)
	{
		infile >> timings[i];
	}
	infile.close();


	//Declare pipes, childpid and set up arguments for the TPM call
	int pipesread[2];
	pid_t childpid;
	std::vector<std::string> argv;
//	md_addr_t addr;
//	md_addr_t argvaddr = params;
	if(params)
	{
		std::string parameters;
		mem->mem_strcpy(Read, params, parameters);
		std::stringstream parse(parameters);
		std::string temp;
		while(parse >> temp)
		{
			argv.push_back(temp);
		}
	}
//	while(addr)
//	{
//		argv.push_back(std::string());
//		mem->mem_strcpy(Read, addr, argv.back());
//		tpm_output("\nArgv(%llx): %llx(%llx)\t",(argvaddr-params)/8,addr,argv.back());
//		argvaddr+=sizeof(md_addr_t);
//		mem->mem_bcopy(Read, argvaddr, &addr, sizeof(md_addr_t));
//	}
//	tpm_output("\n");

	//Insert the actual TPM call into arguments (at the beginning)
	switch(call_num)
	{
	case 18:
		argv.insert(argv.begin(),"createek");
		break;
	case 19:
		argv.insert(argv.begin(),"createkey");
		break;
	case 30:
		argv.insert(argv.begin(),"dumpkey");
		break;
	case 32:
		argv.insert(argv.begin(),"evictkey");
		break;
	case 33:
		argv.insert(argv.begin(),"extend");
		break;
	case 34:
		argv.insert(argv.begin(),"flushspecific");
		break;
	case 49:
		argv.insert(argv.begin(),"loadkey");
		break;
//	case 57:
//		argv.insert(argv.begin(),"nv_definespace");
//		break;
//	case 58:
//		argv.insert(argv.begin(),"nv_readvalue");
//		break;
//	case 59:
//		argv.insert(argv.begin(),"nv_writevalue");
//		break;
	case 62:
		argv.insert(argv.begin(),"pcrread");
		break;
	case 63:
		argv.insert(argv.begin(),"pcrreset");
		break;
	case 68:
		argv.insert(argv.begin(),"quote");
		break;
	case 70:
		argv.insert(argv.begin(),"random");
		break;
	case 78:
		argv.insert(argv.begin(),"savestate");
		break;
	case 79:
		argv.insert(argv.begin(),"sealfile");
		break;
	case 90:
		argv.insert(argv.begin(),"signfile");
		break;
//	case 92:
//		argv.insert(argv.begin(),"takeown");
//		break;
//	case 95:
//		argv.insert(argv.begin(),"tpmbios");
//		break;
//	case 97:
//		argv.insert(argv.begin(),"tpminit");
//		break;
//	case 98:
//		argv.insert(argv.begin(),"tpmreset");
//		break;
	case 101:
		argv.insert(argv.begin(),"unsealfile");
		break;
	case 105:
		argv.insert(argv.begin(),"verifyfile");
		break;

	//These are just for testing, don't really need them.
	case 106:
		argv.insert(argv.begin(),"/bin/echo");
		break;
	case 107:
		argv.insert(argv.begin(),"/usr/bin/env");
		break;
	case 108:
		//Any case, do nothing
		break;
	default:
		fprintf(stderr,"Uncurrently unsupported api_call (%lld)\n",call_num);
		argv.insert(argv.begin(),"no_command");
		break;
	}

	//Ensure that we use the copy of the TPM code that is located in the current working directory
	if(call_num < 106)
	{
		argv[0] = "./" + argv[0];
	}

	if(pipe(pipesread) < 0)
	{
		fprintf(stderr,"Pipe failed\n");
		return NULL;
	}
	if((childpid=vfork()) < 0)
	{
		fprintf(stderr,"Fork failed\n");
		return NULL;
	}

	//The TPM call
	if(childpid==0)
	{
		//Do this so execve doesn't complain
		char **param = new char*[argv.size()+1];
		for(size_t i=0;i<argv.size();i++)
		{
//			tpm_output("\nProcessing(%ld): %s",argv[i].size(),argv[i].c_str());
			param[i] = new char[argv[i].size()+1];
			for(size_t j=0;j<argv[i].size();j++)
			{
				param[i][j] = argv[i][j];
			}
			param[i][argv[i].size()] = '\0';
		}
		param[argv.size()] = NULL;
		tpm_output("Calling %s\t",argv[0].c_str());

		//Set up pipes so output is given back to parent
		close(pipesread[0]);
		dup2(pipesread[1],STDOUT_FILENO);
		close(pipesread[1]);

		//Set up environment variables
		char * envp[5];
		for(int i=0;i<4;i++)
		{
			envp[i] = new char[40];
		}
		strcpy(envp[0],TPM_PORT);
		strcpy(envp[1],TPM_SERVER_PORT);
		strcpy(envp[2],TPM_PATH);
		strcpy(envp[3],TPM_SERVER);
		envp[4] = NULL;

//		RDTSC(start_time);
//		//For testing, we don't really need to go out to the TPM anyway...
//		argv[0] = "random";
//		param[0] = NULL;

		//Execute TPM call
		int retval = execve(argv[0].c_str(), param, envp);
		fprintf(stdout,"Execvp failed(%d): %d, %d\n", getpid(), retval, errno);
		perror("");
		for(int i=0;i<4;i++)
		{
			delete [] envp[i];
		}

		_exit(1);
		return NULL;
	}
	close(pipesread[1]);

	//Wait for child response
	pollfd fds[2];
	fds[1].fd = pipesread[0];
	fds[1].events = POLLIN | POLLPRI;
	fds[0].fd = -1;
//	fprintf(stderr,"Waiting for %d\n",childpid);
	int waitid = poll(fds, 2, 100000);
	if(waitid<0)
	{
		fprintf(stderr,"Error in poll fds\n");
		return NULL;
	}
//	fprintf(stderr,"Events fds %d\n",fds[1].revents);

	//Handle TPM call (looking for a read event)
	//Here is where we need to parse out the result from the output data
	char buffer[TPM_RESPONSE_BUFFER];
	if(fds[1].revents&1)
	{
		int size = read(pipesread[0],buffer,TPM_RESPONSE_BUFFER);
		buffer[size] = '\0';
		fprintf(stderr, "Read(%d): %s",size,buffer);
		char retbuf[TPM_RESPONSE_BUFFER] = "\0";
		switch(call_num)
		{
		case 33:
			if(sscanf(buffer,"New value of PCR[%lld]: %s",&(regs->regs_R[MD_REG_V0]),retbuf) >= TPM_RESPONSE_BUFFER)
			{
				fprintf(stderr, "TPM_RESPONSE_BUFFER is not big enough for our call\n");
				retbuf[TPM_RESPONSE_BUFFER - 1] = '\0';
			}
			mem->mem_bcopy(Write, retloc, retbuf, strlen(retbuf));
			break;
		case 49:
			sscanf(buffer,"New Key Handle = %llx",&(regs->regs_R[MD_REG_V0]));
			mem->mem_bcopy(Write, retloc, &(regs->regs_R[MD_REG_V0]), sizeof(md_gpr_t));
			break;
		case 62:
			if(sscanf(buffer,"Current value of PCR %lld: %s",&(regs->regs_R[MD_REG_V0]),retbuf) >= TPM_RESPONSE_BUFFER)
			{
				fprintf(stderr, "TPM_RESPONSE_BUFFER is not big enough for our call\n");
				retbuf[TPM_RESPONSE_BUFFER - 1] = '\0';
			}
			mem->mem_bcopy(Write, retloc, retbuf, strlen(retbuf));
			break;
		}

		//When the TPM locks you out.
		if(std::string(retbuf) == "Error Defend lock running from TPM_CreateKey")
		{
			mem->mem_bcopy(Write, retloc, &buffer[size], 1);
		}
	}

	//Get return value for the child. Unfortunately, the child doesn't necessarily return anything useful.
	int statloc = 0;
//	tpm_output("Last wait for %d\n",childpid);
	waitid = waitpid(childpid,&statloc,WNOHANG);
//	tpm_output("received %d\n",statloc);
	if(!regs->regs_R[MD_REG_V0])
	{
		regs->regs_R[MD_REG_V0] = statloc;
	}
	close(pipesread[0]);
	close(pipesread[1]);

	return 0;
}
#endif

#undef RDTSC
#undef TPM_BUFFER_SIZE
#undef TPM_RESPONSE_BUFFER
#undef TEST_SPEED
#undef TPM_FIFO
#undef TPM_SRT

#undef TPM_DATA_NAME
#undef TPM_PORT
#undef TPM_SERVER_PORT
#undef TPM_PATH
#undef TPM_SERVER

#undef TPM_PROBABILITY
#undef TPM_DEBUG
#undef TPM_SAMPLE_SIZE
