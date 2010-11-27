///////////////////////////////////////////////
///				SynaPS3devlib 				///
///	          by n4ru && methionine_		///
/// 	Compatible with Sony PS3 SDK 3.41	///
///////////////////////////////////////////////
#ifndef __SYNAPS3DEV_H
#define __SYNAPS3DEV_H

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
#include <iostream>
#include <fstream>
#include "syscall8.h" 

#define PAYLOAD_CAPS_SYSCALL36	1
#define PAYLOAD_CAPS_SYSCALL8	2
#define PAYLOAD_CAPS_PEEKPOKE	4
#define PAYLOAD_CAPS_SYSCALL35	8

unsigned char GetPayloadCaps() {
	unsigned char ret = 0;
    if(syscall35("/dev_hdd0", "/dev_hdd0") == 0) {
		ret |= PAYLOAD_CAPS_SYSCALL35;
    }
    if(sys8_enable(0) > 0) {
        ret |= PAYLOAD_CAPS_SYSCALL8;
    }
	uint64_t oldValue = peekq(0x80000000000505d0ULL);
    if(peekq(0x80000000000505d0ULL) == oldValue) { 
        ret |= PAYLOAD_CAPS_PEEKPOKE;
    }
	if(syscall36("/dev_bdvd") == 0) {
		ret |= PAYLOAD_CAPS_SYSCALL36;
	}
    return ret;
}

uint32_t syscall35hermes(const char *old_path, const char *new_path) {
	if(sys8_enable(0) > 0) {
		// This needs to be fixed asap to allow more than one mount redirection
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
		return 0;
	}
}

#endif /* __SYNAPS3DEV_H */
