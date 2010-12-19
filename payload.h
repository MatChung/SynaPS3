///////////////////////////////////////////////
///				SynaPS3devlib 				///
///	          by n4ru && methionine_		///
/// 	Compatible with Sony PS3 SDK 3.41	///
///////////////////////////////////////////////
///					payload.h				///
///	Functions related to dongle payloads.	///
///////////////////////////////////////////////
#ifndef __PAYLOAD_H
#define __PAYLOAD_H

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
#include "synaps3.h"

#define PAYLOAD_CAPS_SYSCALL36	1
#define PAYLOAD_CAPS_SYSCALL8	2
#define PAYLOAD_CAPS_PEEKPOKE	4
#define PAYLOAD_CAPS_SYSCALL35	8

static char FirmwareVersion[10]="00.0000";

unsigned char GetPayloadCaps() {
	unsigned char ret = 0;
    if(syscall35("/dev_hdd0", "/dev_hdd0") != 0x80010003) {
		ret |= PAYLOAD_CAPS_SYSCALL35;
    }
    if(sys8_enable(0) > 0) {
        ret |= PAYLOAD_CAPS_SYSCALL8;
    }
	if (strcmp(FirmwareVersion, "03.4100") == 0){
		uint64_t oldValue = syscall6(0x80000000000505d0ULL);
		syscall7(0x80000000000505d0ULL, 0xE92296887C0802A6ULL);
		if(syscall6(0x80000000000505d0ULL) == 0xE92296887C0802A6ULL) {
			syscall7(0x80000000000505d0ULL, oldValue);
			ret |= PAYLOAD_CAPS_PEEKPOKE;
		}
	} else {
		uint64_t oldValue = syscall6(0x80000000000505d0ULL);
		if(syscall6(0x80000000000505d0ULL) == oldValue) { 
			ret |= PAYLOAD_CAPS_PEEKPOKE;
		}
	}
	if(syscall36("/dev_bdvd") != 0x80010003) {
		ret |= PAYLOAD_CAPS_SYSCALL36;
	}
    return ret;
}

#endif /* __PAYLOAD_H */
