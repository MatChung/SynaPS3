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
#include "synaps3.h"

char eboot_path[256]; 
char game_path[] = "/dev_usb003/GAMEZ/BCUS98111"; 
char data_path[] = "/dev_usb003/PS3/game"; 

int main() {
    LoadIOFSModules();										// Loads IO and FS Cell modules
    
    if(IsBlurayGame()) {									// Do we have a PS3 game inserted?
        if(GetPayloadCaps() & PAYLOAD_CAPS_SYSCALL35) {		// Are we using PL3 or PL3Dev?
            RedirectGameData(data_path);					// Mount our new game install point
        }
    }
    
    MountBDVD(game_path);									// Mount the PS3 Game
    
    if(GetPayloadCaps() & PAYLOAD_CAPS_PEEKPOKE) {			// Does our Payload have Peek/Poke?
	    FixController();									// If so, apply the Controller fix.
    }
    
    sprintf(eboot_path, '%s/PS3_GAME/USRDIR/EBOOT.BIN', game_path);
    BootGame(eboot_path, 0, STACK_1M);						// Let's boot directly, with 3071 priority and a 1M stack.	

	UnloadIOFSModules();									// Unloads IO and FS Cell modules
	sys_process_exit(1); 									// Exit
}