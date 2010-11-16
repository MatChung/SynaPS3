///////////////////////////////////////////////
///					SynaPS3lib 				///
///	          by n4ru && methionine_		///
/// 	Compatible with Sony PS3 SDK 3.41	///
///////////////////////////////////////////////
#ifndef __SYNAPS3_H
#define __SYNAPS3_H

#include <sys/spu_initialize.h> 
#include <sys/ppu_thread.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <stdarg.h> 
#include <assert.h> 
#include <string.h> 
#include <dirent.h> 
#include <unistd.h> 
#include <fcntl.h> 
#include <time.h> 
#include <math.h> 
#include <stddef.h> 
#include <sys/stat.h> 
#include <sys/process.h> 
#include <sys/memory.h> 
#include <sys/timer.h> 
#include <sys/return_code.h> 
#include <cell/gcm.h> 
#include <cell/pad.h> 
#include <cell/keyboard.h> 
#include <cell/sysmodule.h> 
#include <cell/dbgfont.h> 
#include <cell/codec/pngdec.h> 
#include <cell/cell_fs.h> 
#include <sysutil/sysutil_sysparam.h> 
#include <sysutil/sysutil_discgame.h> 
#include <sysutil/sysutil_msgdialog.h> 
#include <sysutil/sysutil_oskdialog.h> 
#include "syscall8.h" 

using namespace cell::Gcm; 

#define PAYLOAD_CAPS_SYSCALL36	1
#define PAYLOAD_CAPS_SYSCALL8	2
#define PAYLOAD_CAPS_PEEKPOKE	4
#define PAYLOAD_CAPS_SYSCALL35	8
/*
PSGroove1.0						syscall36
PSGroove1.1/Hermesv1/Hermesv2	syscall36, Peek & Poke, Controller Fix
Hermesv3/Hermesv4				syscall36, Peek & Poke, syscall8, syscall35, Controller Fix
PL3								syscall36, syscall35, Controller Fix
PL3Dev							syscall36, Peek & Poke, syscall35, Controller Fix
*/

// Same as sys/process.h -> SYS_PROCESS_PRIMARY_STACK_SIZE_*
#define STACK_1M	0x0000000000000070ULL
#define STACK_512K	0x0000000000000060ULL
#define STACK_256K	0x0000000000000050ULL
#define STACK_128K	0x0000000000000040ULL
#define STACK_96K	0x0000000000000030ULL
#define STACK_64K	0x0000000000000020ULL
#define STACK_32K	0x0000000000000010ULL

static char FirmwareVersion[10]="00.0000";

uint32_t syscall35(const char *old_path, const char *new_path)
{
	if(system_call_2(35, "/dev_bdvd", "dev_bdvd") != 0) {
		if(sys8_enable(0) > 0) {
			// syscall8 -> syscall35 conversion starts here
			typedef struct
			{
			path_open_entry entries[2];
			char arena[0x2000];
			} path_open_table;
			path_open_table open_table;
			uint64_t dest_table_addr;	
			sys8_path_table(0ULL);
			dest_table_addr= 0x80000000007FF000ULL-((sizeof(path_open_table)+15) & ~15);
			open_table.entries[0].compare_addr= ((uint64_t) &open_table.arena[0]) - ((uint64_t) &open_table) + dest_table_addr;
			open_table.entries[0].replace_addr= ((uint64_t) &open_table.arena[0x800])- ((uint64_t) &open_table) + dest_table_addr;
			open_table.entries[1].compare_addr= 0ULL;
			cellFsMkdir(new_path, CELL_FS_DEFAULT_CREATE_MODE_1);
			cellFsChmod(new_path, 0777);      
			strncpy(&open_table.arena[0], old_path, 0x100);
			strncpy(&open_table.arena[0x800], new_path, 0x800);
			open_table.entries[0].compare_len= strlen(&open_table.arena[0]);
			open_table.entries[0].replace_len= strlen(&open_table.arena[0x800]);
			sys8_memcpy(dest_table_addr, (uint64_t) &open_table, sizeof(path_open_table));
			sys8_path_table( dest_table_addr);
			// syscall8 -> syscall35 conversion ends here
		}
	} else {
		system_call_2(35, (uint32_t) old_path, (uint32_t) new_path);
		return_to_user_prog(uint32_t);
	}
}

void syscall36(char *game_path) {
	if(system_call_2(35, "/dev_bdvd", game_path) != 0) {
		system_call_1(36, (uint32_t) path);
	} else {
		system_call_2(35, "/dev_bdvd", game_path);
		system_call_2(35, "/app_home", game_path);
	}
}

void pokeq(uint64_t addr, uint64_t val) {
    system_call_2(7, addr, val); 
}

uint64_t peekq(uint64_t addr) { 
	uint64_t out; 
	system_call_2(6,addr,out); 
	return out; 
} 

unsigned char GetPayloadCaps() {
    unsigned char ret;
    ret = 0;

    if(syscall35("/dev_hdd0", "/dev_hdd0") == 0) {
		ret |= PAYLOAD_CAPS_SYSCALL35;
    }

    if(sys8_enable(0) > 0) {
        ret |= PAYLOAD_CAPS_SYSCALL8;
    }

    uint64_t oldValue = peekq(0x80000000000505d0UL);
    pokeq(0x80000000000505d0ULL, 0xE92296887C0802A6ULL); 
    if(peekq(0xE92296887C0802A6ULL) == 0xE92296887C0802A6ULL) { 
    	pokeq(0x80000000000505d0ULL, oldValue);
        ret |= (PAYLOAD_CAPS_PEEKPOKE);
    }
	ret |= PAYLOAD_CAPS_SYSCALL36;
    return ret;
}

int ReadFirmwareVersion(char * FirmwareVersion) // ReadFirmwareVersion(FirmwareVersion); returns FW (03.4100)
{
  FILE *fp = fopen ("/dev_flash/vsh/etc/version.txt", "r" );  
  if ( fp != NULL )
  {	
    char line [ 16 ];
    if (fgets ( line, sizeof line, fp ) != NULL) {
      sprintf(FirmwareVersion, "%s", strstr(line, "release:")+8);    
      return 0;
    } else {
      return -2;
    }
  }else{
    return -1;
  }
}

void Firmware342Fix()
{
	if(GetPayloadCaps() & PAYLOAD_CAPS_PEEKPOKE) {
		if (strcmp(FirmwareVersion, "03.0100")==0){
			pokeq(0x800000000004ca38ULL, 0x4BFFFFD440990024ULL);
			pokeq(0x80000000000547fcULL, 0x6000000038de0007ULL);
			pokeq(0x800000000005487cULL, 0x480000a02f840004ULL);
		}
		if (strcmp(FirmwareVersion, "03.1500")==0){
			pokeq(0x800000000004ED5CULL, 0x4BFFFFD440990024ULL);          
			pokeq(0x8000000000056D84ULL, 0x6000000038de0007ULL);   
			pokeq(0x8000000000056df4ULL, 0x480000a02f840004ULL);
		}
		if (strcmp(FirmwareVersion, "03.4100")==0){
			pokeq(0x800000000004F290ULL, 0x4BFFFFD440990024ULL);
			pokeq(0x8000000000057398ULL, 0x6000000038de0007ULL);  
			pokeq(0x8000000000057408ULL, 0x480000a02f840004ULL);
		}	
   }
}

bool IsBlurayGame() {
    struct stat stPath;
    return (stat("/dev_bdvd", &stPath) == 0);
} 

bool IsPSXGame() {
    struct stat stPath;
    return ((stat("/dev_ps2disc", &stPath) == 0)||(stat("/dev_ps1disc", &stPath) == 0));
} 

void BootGame(char eboot_path[256], bool highPriority, unsigned long long stackSize) {
    if (highPriority) {
        sys_game_process_exitspawn2(eboot_path, NULL, NULL, NULL, 0, 1001, stackSize);
    } else {
        sys_game_process_exitspawn2(eboot_path, NULL, NULL, NULL, 0, 3071, stackSize);
    }
}

void FixController() {
	if(GetPayloadCaps() & PAYLOAD_CAPS_SYSCALL8) {
        sys8_perm_mode(2);
    } else if(GetPayloadCaps() & PAYLOAD_CAPS_PEEKPOKE) {
		//if (strcmp(FirmwareVersion, "03.4100")==0){
			pokeq(0x80000000000505d0ULL, 0xE92296887C0802A6ULL); 
		//}	
    }
}

void MountBDVD(char *game_path) {
    if(GetPayloadCaps() & PAYLOAD_CAPS_SYSCALL35) { 
        syscall35("/dev_bdvd", game_path); 
        syscall35("/app_home", game_path); 
	}
    if(GetPayloadCaps() & PAYLOAD_CAPS_SYSCALL36) { 
        syscall36(game_path); 
	} 
}

void LoadIOFSModules() {
    cellSysmoduleLoadModule(CELL_SYSMODULE_IO);
    cellSysmoduleLoadModule(CELL_SYSMODULE_FS);
}

void UnloadIOFSModules() {
    cellSysmoduleUnloadModule(CELL_SYSMODULE_IO);
    cellSysmoduleUnloadModule(CELL_SYSMODULE_FS);
}

#endif /* __SYNAPS3_H */