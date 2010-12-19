///////////////////////////////////////////////
///				SynaPS3devlib 				///
///	          by n4ru && methionine_		///
/// 	Compatible with Sony PS3 SDK 3.41	///
///////////////////////////////////////////////
///					flash.h					///
///	dev_flash or FLASH related functions.	///
///////////////////////////////////////////////
#ifndef __FLASH_H
#define __FLASH_H

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
#include "syscalls.h"
#include "system.h"

#define MNT_FLASH		0x5F666C6173680000ULL
#define MNT_FLASH0		0x5F666C6173683000ULL
#define MNT_DEVICE		"CELL_FS_IOS:BUILTIN_FLSH1"
#define MNT_FILESYSTEM	"CELL_FS_FAT"
#define MNT_POINT		"/dev_flash"

static char FirmwareVersion[10]="00.0000";

int MountFlash(char* fla) {
    struct stat stPath;
    if(stat(fla, &stPath) == 0) {
		Mount(fla, "/dev_flash/");
		return 0;
	}
}

// LV2_FLASH - Unlock/Lock dev_flash0 for writing.
void LV2_FLASH(bool WrFlash) {
	if (strcmp(FirmwareVersion, "03.4100")==0){
		if (WrFlash) {
		
		} else {
			
		}
	}
}

#endif /* __FLASH_H */
