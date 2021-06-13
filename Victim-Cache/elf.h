/*
 * Header files and constant values for ELF format support Weidan Wu 10/22/2010
 */

//ELF header
struct Elf64_External_Ehdr
{
	byte_t 		e_ident[16];			//ELF "magic number"
	half_t		e_type;				//Identifies object file type
	half_t		e_machine;			//Specifies required architecture
	word_t		e_version;			//Identifies object file version
	qword_t		e_entry;			//Entry point virtual address
	qword_t		e_phoff;			//Program header table file offset
	qword_t		e_shoff;			//Section header table file offset
	word_t		e_flags;			//Processor-specific flags
	half_t		e_ehsize;			//ELF header size in bytes
	half_t		e_phentsize;			//Program header table entry size
	half_t		e_phnum;			//Program header table entry count
	half_t		e_shentsize;			//Section header table entry size
	half_t		e_shnum;			//Section header table entry count
	half_t		e_shstrndx;			//Section header string table index
};

//Program header
struct Elf64_External_Phdr
{
	word_t		p_type;				//Identifies program segment type
	word_t		p_flags;			//Segment flags
	qword_t		p_offset;			//Segment file offset
	qword_t		p_vaddr;			//Segment virtual address
	qword_t		p_paddr;			//Segment physical address
	qword_t		p_filesz;			//Segment size in file
	qword_t		p_memsz;			//Segment size in memory
	qword_t		p_align;			//Segment alignment, file & memory
};

//Section header
struct Elf64_External_Shdr
{
	unsigned char	sh_name[4];			//Section name, index in string tbl
	unsigned char	sh_type[4];			//Type of section
	unsigned char	sh_flags[8];			//Miscellaneous section attributes
	unsigned char	sh_addr[8];			//Section virtual addr at execution
	unsigned char	sh_offset[8];			//Section file offset
	unsigned char	sh_size[8];			//Size of section in bytes
	unsigned char	sh_link[4];			//Index of another section
	unsigned char	sh_info[4];			//Additional section information
	unsigned char	sh_addralign[8];		//Section alignment
	unsigned char	sh_entsize[8];			//Entry size if section holds table
};

//Fields in e_ident[].
#define EI_MAG0			0			//File identification byte 0 index
#define EI_MAG1			1			//File identification byte 1 index
#define EI_MAG2			2			//File identification byte 2 index
#define EI_MAG3			3			//File identification byte 3 index

#define ELFMAG0			0x7F			//Magic number byte 0
#define ELFMAG1			'E'			//Magic number byte 1
#define ELFMAG2			'L'			//Magic number byte 2
#define ELFMAG3			'F'			//Magic number byte 3

#define ELFCLASSNONE		0			//Invalid class
#define ELFCLASS32		1			//32-bit objects
#define ELFCLASS64		2			//64-bit objects
#define EI_CLASS		4			//File class

#define EI_DATA			5			//Data encoding
#define ELFDATANONE		0			//Invalid data encoding
#define ELFDATA2LSB		1			//2's complement, little endian
#define ELFDATA2MSB		2			//2's complement, big endian

#define EI_VERSION		6			//File version

#define EI_OSABI		7			//Operating System/ABI indication
#define ELFOSABI_NONE		0			//UNIX System V ABI
#define ELFOSABI_HPUX		1			//HP-UX operating system
#define ELFOSABI_NETBSD		2			//NetBSD
#define ELFOSABI_LINUX		3			//GNU/Linux
#define ELFOSABI_HURD		4			//GNU/Hurd
#define ELFOSABI_SOLARIS	6			//Solaris
#define ELFOSABI_AIX		7			//AIX
#define ELFOSABI_IRIX		8			//IRIX
#define ELFOSABI_FREEBSD	9			//FreeBSD
#define ELFOSABI_TRU64		10			//TRU64 UNIX
#define ELFOSABI_MODESTO	11			//Novell Modesto
#define ELFOSABI_OPENBSD	12			//OpenBSD
#define ELFOSABI_OPENVMS	13			//OpenVMS
#define ELFOSABI_NSK		14			//Hewlett-Packard Non-Stop Kernel
#define ELFOSABI_AROS		15			//Amiga Research OS
#define ELFOSABI_ARM		97			//ARM
#define ELFOSABI_STANDALONE	255			//Standalone (embedded) application

#define EI_ABIVERSION		8			//ABI version
#define EI_PAD			9			//Start of padding bytes

//Values for e_type, which identifies the object file type.
#define ET_NONE			0			//No file type
#define ET_REL			1			//Relocatable file
#define ET_EXEC			2			//Executable file
#define ET_DYN			3			//Shared object file
#define ET_CORE			4			//Core file
#define ET_LOOS			0xFE00			//Operating system-specific
#define ET_HIOS			0xFEFF			//Operating system-specific
#define ET_LOPROC		0xFF00			//Processor-specific
#define ET_HIPROC		0xFFFF			//Processor-specific

//Alpha backend magic number. Written in the absence of an ABI.
#define EM_ALPHA		0x9026

//See the above comment before you add a new EM_* value here.

//Values for e_version.
#define EV_NONE			0			//Invalid ELF version
#define EV_CURRENT		1			//Current version

//Values for program header, p_type field.
#define PT_NULL			0			//Program header table entry unused
#define PT_LOAD			1			//Loadable program segment
#define PT_DYNAMIC		2			//Dynamic linking information
#define PT_INTERP		3			//Program interpreter
#define PT_NOTE			4			//Auxiliary information
#define PT_SHLIB		5			//Reserved, unspecified semantics
#define PT_PHDR			6			//Entry for header table itself
#define PT_TLS			7			//Thread local storage segment
#define PT_LOOS			0x60000000		//OS-specific
//Removed as conflict for November 2010 M-Sim release
//#define PT_GNU_STACK		0x6474e551		//GNU STACK I don't know what is that... weidan 10262010
#define PT_HIOS			0x6fffffff		//OS-specific
#define PT_LOPROC		0x70000000		//Processor-specific
#define PT_HIPROC		0x7FFFFFFF		//Processor-specific

#define PT_GNU_EH_FRAME		(PT_LOOS + 0x474e550)	//Frame unwind information
#define PT_SUNW_EH_FRAME	PT_GNU_EH_FRAME		//Solaris uses the same value
#define PT_GNU_STACK		(PT_LOOS + 0x474e551)	//Stack flags
#define PT_GNU_RELRO		(PT_LOOS + 0x474e552)	//Read-only after relocation
