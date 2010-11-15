///////////////////////////////////////////////
///					SynaPS3lib 				
///	          by n4ru && methionine_		
/// 	Compatible with Sony PS3 SDK 3.41	
///////////////////////////////////////////////
///
/// void Mount(const char *old_path, const char *new_path)
/// - Mounts second argument to first.
///
/// void MountBDVD(char *path) 
/// - Mounts argument to /dev_bdvd.
///
/// void MountPS2Disc(const char *ps2_path)
/// - Mounts argument to /dev_ps2disc. Cannot launch PS2 games.
/// - NOTE: Is actually a #define!
///
/// void MountPS1Disc(const char *ps1_path)
/// - Mounts argument to /dev_ps1disc. Cannot launch PS1 games.
/// - NOTE: Is actually a #define!
///
/// void RedirectGameData(const char *data_path)
/// - Mounts argument to /dev_hdd0/game. Used to redirect game installs.
/// - NOTE: Is actually a #define!
///
/// void BootGame(char eboot_path[256], bool highPriority, const char *stack)
/// - Boots eboot at first argument, with priority given by second argument (true = 1001, false = 3071), with stack size given by third argument.
///
///	bool IsBlurayGame()
/// - Returns true if a valid PS3 game is inserted.
///
/// int GetPayloadType()
/// - Returns payload type. One of PAYLOAD_TYPE #defines.
///
/// bool HasPeekPoke()
/// - Returns true if the payload has Peek and Poke.
///
/// void FixController()
/// - If the payload has Peek/Poke, activates the controller fix.
///
/// void pokeq(uint64_t addr, uint64_t val) 
/// - Modifies first argument address in memory to second argument's value.
///
/// uint64_t peekq(uint64_t addr) 
/// - Returns the value at first argument address.
///
/// void LoadIOFSModules()
/// - Loads the IO and FS modules
///
/// void UnloadIOFSModules()
/// - Unloads the IO and FS modules
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
#define PAYLOAD_CAPS_PEEKPOKE	2
#define PAYLOAD_CAPS_SYSCALL8	4
#define PAYLOAD_CAPS_SYSCALL35	8
/*
PSGroove 						1
PSGroove1.1/Hermesv1/Hermesv2	3
Hermesv3/Hermesv4				7
Old PL3							8  (9 with the hacked syscall36)
New PL3							9
Old PL3Dev						10 (11 with the hacked syscall36)
New PL3Dev						11
*/
/* Same as sys/process.h -> SYS_PROCESS_PRIMARY_STACK_SIZE_* */
#define STACK_1M	0x0000000000000070ULL
#define STACK_512K	0x0000000000000060ULL
#define STACK_256K	0x0000000000000050ULL
#define STACK_128K	0x0000000000000040ULL
#define STACK_96K	0x0000000000000030ULL
#define STACK_64K	0x0000000000000020ULL
#define STACK_32K	0x0000000000000010ULL

#define syscall35(x,y)		system_call_1(35, (uint32_t) x, (uint32_t) y);  
#define Mount(x,y)			system_call_1(35, (uint32_t) x, (uint32_t) y); 
#define MountPS2Disc(x)		system_call_2(35, "/dev_ps2disc", (uint32_t) x);
#define MountPS1Disc(x)		system_call_2(35, "/dev_ps1disc", (uint32_t) x);
#define RedirectGameData(x)	system_call_2(35, "/dev_hdd0/game", (uint32_t) x);

void syscall36(uint64_t game_path) {
	if((system_call_1(36, "/dev_bdvd")) == 0) {
		system_call_1(36, game_path);
	} else {
		system_call_2(35, "/dev_bdvd", game_path);
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

bool IsBlurayGame() {
    struct stat stFile;
    return (stat("/dev_bdvd/PS3_GAME/PARAM.SFO", &stFile) == 0);
} 

void BootGame(char eboot_path[256], bool highPriority, unsigned long long stackSize) {
    if (highPriority) {
        sys_game_process_exitspawn2(eboot_path, NULL, NULL, NULL, 0, 1001, stackSize);
    } else {
        sys_game_process_exitspawn2(eboot_path, NULL, NULL, NULL, 0, 3071, stackSize);
    }
}

unsigned char GetPayloadCaps() {
    unsigned char ret;
    ret = 0;
    
    if(syscall35("/dev_hdd0", "/dev_hdd0") == 0) {
		ret |= PAYLOAD_CAPS_SYSCALL35;
    }
	
    if(syscall36("/dev_bdvd") == 0) {
		ret |= PAYLOAD_CAPS_SYSCALL36;
    }
    
    if(sys8_enable(0) > 0) {
        ret |= PAYLOAD_CAPS_SYSCALL8;
    }
    
    uint64_t oldValue = peekq(0x80000000000505d0UL);
    pokeq(0x80000000000505d0ULL, 0xE92296887C0802A6ULL); 
    if(peekq(0xE92296887C0802A6ULL) == 0xE92296887C0802A6ULL) { 
    	pokeq(0x80000000000505d0ULL, 0xE92296887C0802A6ULL);
        ret |= (PAYLOAD_CAPS_PEEKPOKE);
    }
    return ret;
}


void FixController() {
	if(GetPayloadCaps() & PAYLOAD_CAPS_SYSCALL8) {
        sys8_perm_mode(2);
    } else if(GetPayloadCaps() & PAYLOAD_CAPS_PEEKPOKE) {
        pokeq(0x80000000000505d0ULL, 0xE92296887C0802A6ULL); 
    }
}

void MountBDVD(char *game_path) {
    if(GetPayloadCaps() & PAYLOAD_CAPS_SYSCALL35) { 
        syscall35("/dev_bdvd", game_path); 
        syscall35("/app_home", game_path); 
	} else if(GetPayloadCaps() & PAYLOAD_CAPS_SYSCALL36) { 
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