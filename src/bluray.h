///////////////////////////////////////////////
///			SynaPS3lib 2011 (c) n4ru		///
///////////////////////////////////////////////
///					bluray.h				///
///			Bluray specific functions.		///
///////////////////////////////////////////////
#ifndef __BLURAY_H
#define __BLURAY_H

#include <unistd.h> 

bool IsBD() {
    struct stat stPath;
    return (stat("/dev_bdvd/PS3_GAME/", &stPath) == 0)||(stat("/dev_bdvd/BDMV/", &stPath) == 0);
} 

bool IsPS3Game() {
    struct stat stPath;
    return (stat("/dev_bdvd/PS3_GAME/", &stPath) == 0);
}

void BootDisc() {
        sys_game_process_exitspawn2("/dev_bdvd/PS3_GAME/USRDIR/EBOOT.BIN", NULL, NULL, NULL, 0, 1001, SYS_PROCESS_PRIMARY_STACK_SIZE_1M);
}

#endif /* __BLURAY_H */
