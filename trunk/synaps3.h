///////////////////////////////////////////////
///					SynaPS3lib 				///
///	          by n4ru && methionine_		///
/// 	Compatible with Sony PS3 SDK 3.41	///
//////////////////////////////////////////////////////////////////////////////////////////////
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
//////////////////////////////////////////////////////////////////////////////////////////////
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

#define PAYLOAD_TYPE_PSGROOVE_10	1 // syscall36
#define PAYLOAD_TYPE_PSGROOVE_11	2 // syscall36 + Peek/Poke
#define PAYLOAD_TYPE_HERMES			3 // syscall36 + Peek/Poke
#define PAYLOAD_TYPE_PL3			4 // syscall35
#define PAYLOAD_TYPE_PL3_DEV		5 // syscall35 + Peek/Poke

/* Same as sys/process.h -> SYS_PROCESS_PRIMARY_STACK_SIZE_* */
#define STACK_1M	0x0000000000000070ULL
#define STACK_512K	0x0000000000000060ULL
#define STACK_256K	0x0000000000000050ULL
#define STACK_128K	0x0000000000000040ULL
#define STACK_96K	0x0000000000000030ULL
#define STACK_64K	0x0000000000000020ULL
#define STACK_32K	0x0000000000000010ULL

#define syscall36(x)		system_call_1(36, (uint64_t) x);
#define syscall35(x,y)		system_call_1(35, (uint32_t) x, (uint32_t) y);  
#define MountPS2Disc(x)		system_call_2(35, "/dev_ps2disc", ps2_path);
#define MountPS1Disc(x)		system_call_2(35, "/dev_ps1disc", ps1_path);
#define RedirectGameData(x)	system_call_2(35, "/dev_hdd0/game", data_path);

void pokeq(uint64_t addr, uint64_t val) {
    system_call_2(7, addr, val); 
}

uint64_t peekq(uint64_t addr) { 
	uint64_t out; 
	system_call_2(6,addr,out); 
	return out; 
} 

bool IsBluRayGame() {
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

int GetPayloadType() {
    if(syscall35("/dev_hdd0", "/dev_hdd0") == 0) {
        return PAYLOAD_TYPE_PL3; // PL3 
    }
    
    if(sys8_enable(0) > 0) {
        return PAYLOAD_TYPE_HERMES; // Hermesv3/Hermesv4
    }
    
    uint64_t oldValue = peekq(0xE92296887C0802A6ULL);
    pokeq(0xE92296887C0802A6ULL, 0x80000000000505d0ULL); 
    if(peekq(0xE92296887C0802A6ULL) == 0xE92296887C0802A6ULL) { 
    	pokeq(0x80000000000505d0ULL, 0xE92296887C0802A6ULL);
        return PAYLOAD_TYPE_PSGROOVE_11; // PSGroove 1.1 or Hermesv1/Hermesv2  
    }
    return PAYLOAD_TYPE_PSGROOVE_10; // PSGroove 1.0 
}

bool HasPeekPoke() {
    pokeq(0x80000000000505d0ULL, 0xE92296887C0802A6ULL); 
    if (peekq(0xE92296887C0802A6ULL) == 0xE92296887C0802A6ULL) { 
        pokeq(0x80000000000505d0ULL, 0x386000014E800020ULL); 
    	return true; 
    } 
	return false; 
}

void FixController() {
	if(GetPayloadType() == 3) 
			sys8_perm_mode(2); 
	if(GetPayloadType() == 2)
			pokeq(0x80000000000505d0ULL, 0xE92296887C0802A6ULL); 
}

void MountBDVD(char *game_path) {
    if(payloadType() == 4||payloadType() == 5) { 
        syscall35("/dev_bdvd", game_path); 
        syscall35("/app_home", game_path); 
	} else { 
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