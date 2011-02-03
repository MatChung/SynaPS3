///////////////////////////////////////////////
///			SynaPS3lib 2011 (c) n4ru		///
///////////////////////////////////////////////
///					system.h				///
///				Core functions.				///
///////////////////////////////////////////////
#ifndef __SYSTEM_H
#define __SYSTEM_H

#include <string.h> 
#include <unistd.h> 
#include <cell/cell_fs.h> 
#include <cell/dbgfont.h> 
#include <cell/codec/pngdec.h>

#define STACK_1M	0x0000000000000070ULL
#define STACK_512K	0x0000000000000060ULL
#define STACK_256K	0x0000000000000050ULL
#define STACK_128K	0x0000000000000040ULL
#define STACK_96K	0x0000000000000030ULL
#define STACK_64K	0x0000000000000020ULL
#define STACK_32K	0x0000000000000010ULL

void exit() {
	sys_process_exit(1);
}

void bootSELF(char eboot_path[256], bool highPriority, unsigned long long stackSize) {
    if (highPriority)
        sys_game_process_exitspawn2(eboot_path, NULL, NULL, NULL, 0, 1001, stackSize);
    else
        sys_game_process_exitspawn2(eboot_path, NULL, NULL, NULL, 0, 3071, stackSize);
}

void initIOFS(bool toggle) {
	if(toggle) {
		cellSysmoduleLoadModule(CELL_SYSMODULE_IO);
		cellSysmoduleLoadModule(CELL_SYSMODULE_FS);
	} else {
		cellSysmoduleUnloadModule(CELL_SYSMODULE_IO);
		cellSysmoduleUnloadModule(CELL_SYSMODULE_FS);
	}
}

#endif /* __SYSTEM_H */
