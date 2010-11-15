#include "synaps3.h"

char eboot_path[256]; 
char game_path[] = "/dev_usb003/GAMEZ/BCUS98111"; 
char data_path[] = "/dev_usb003/PS3/game"; 

int main()
{
	LoadIOFSModules();								   // Loads IOFS
	if(IsBlurayGame()) 								   // Do we have a PS3 game inserted?
	{												   // If we do
		if(GetPayloadType() == 4||GetPayloadType == 5) // Are we using PL3 or PL3Dev?
			{ 										   // If we are
				RedirectGameData(data_path);		   // Mount our new game install point
			}
		MountBDVD(game_path);				   		   // Mount	the PS3 Game
		if(HasPeekPoke())						       // Does our Payload have Peek/Poke?
			FixController();					       // If so, apply the Controller fix.
	sprintf(eboot_path, '%s/PS3_GAME/USRDIR/EBOOT.BIN', game_path);
	BootGame(eboot_path, 0, STACK_1M);				   // Let's boot directly, with 3071 priority and a 1M stack.	
	}
	UnloadIOFSModules();							   // Unloads IOFS
	sys_process_exit(1); 							   // Exit
}