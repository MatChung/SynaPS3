///////////////////////////////////////////////
///				SynaPS3lib 					///
///	          by n4ru && methionine_		///
/// 	Compatible with Sony PS3 SDK 3.41	///
///////////////////////////////////////////////
///					flash.h					///
///	dev_flash or FLASH related functions.	///
///////////////////////////////////////////////
#ifndef __FLASH_H
#define __FLASH_H

#include <unistd.h> 
#include "system.h"

int MountFlash(char* fla) {
    struct stat stPath;
    if(stat(fla, &stPath) == 0) {
		Mount(fla, "/dev_flash/");
	}
	return 0;
}

#endif /* __FLASH_H */
