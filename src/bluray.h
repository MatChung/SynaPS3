///////////////////////////////////////////////
///					SynaPS3lib 				///
///	          by n4ru && methionine_		///
/// 	Compatible with Sony PS3 SDK 3.41	///
///////////////////////////////////////////////
///					bluray.h				///
///			Bluray specific functions.		///
///////////////////////////////////////////////
#ifndef __BLURAY_H
#define __BLURAY_H

#include <sys/stat.h>
#include "syscalls.h"
#include "system.h"

bool IsBluray() {
    struct stat stPath;
    return (stat("/dev_bdvd/PS3_GAME/", &stFile) == 0)||(stat("/dev_bdvd/BDMV/", &stFile) == 0);
} 

bool IsPS3Game() {
    struct stat stPath;
    return (stat("/dev_bdvd/PS3_GAME/", &stFile) == 0);
} 

void MountBluray(char *game_path) {
	if(stat(game_path, &stPath) == 0) {					
		if(old_path == "/dev_bdvd") {					
			syscall36(game_path);
		}
	} else {				
		Mount("/app_home", game_path);
	}
}

#endif /* __BLURAY_H */
