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

#include "system.h"

bool IsBD() {
    struct stat stPath;
    return (stat("/dev_bdvd/PS3_GAME/", &stPath) == 0)||(stat("/dev_bdvd/BDMV/", &stPath) == 0);
} 

bool IsPS3Game() {
    struct stat stPath;
    return (stat("/dev_bdvd/PS3_GAME/", &stPath) == 0);
} 

void MountBD(char *game_path) {		
		if(syscall35("/dev_hdd0", "/dev_hdd0") != 0x80010003) {
			syscall35("/dev_bdvd", game_path);
			syscall35("/app_home", game_path);
		} else {
			syscall36(game_path);
		}
}

#endif /* __BLURAY_H */
