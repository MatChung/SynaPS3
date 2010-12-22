///////////////////////////////////////////////
///			SynaPS3lib 2010 (c) n4ru		///
///////////////////////////////////////////////
///					patches.h				///
///			Game and system patches.		///
///////////////////////////////////////////////
#ifndef __PATCHES_H
#define __PATCHES_H

#include "system.h" 

void Firmware342Fix()
{
	if(syscall6(0x8000000000000000ULL) != 0x80010003) {
		if (strcmp(FirmwareVersion, "03.0100")==0){
			syscall7(0x800000000004ca38ULL, 0x4BFFFFD440990024ULL);
			syscall7(0x80000000000547fcULL, 0x6000000038de0007ULL);
			syscall7(0x800000000005487cULL, 0x480000a02f840004ULL);
		}
		if (strcmp(FirmwareVersion, "03.1500")==0){
			syscall7(0x800000000004ED5CULL, 0x4BFFFFD440990024ULL);          
			syscall7(0x8000000000056D84ULL, 0x6000000038de0007ULL);   
			syscall7(0x8000000000056df4ULL, 0x480000a02f840004ULL);
		}
		if (strcmp(FirmwareVersion, "03.4100")==0){
			syscall7(0x800000000004F290ULL, 0x4BFFFFD440990024ULL);
			syscall7(0x8000000000057398ULL, 0x6000000038de0007ULL);  
			syscall7(0x8000000000057408ULL, 0x480000a02f840004ULL);
		}	
	}
}

void ControllerFix() {													
    if(sys8_enable(0) > 0) {											
        sys8_perm_mode(2);												
    } else {															
		if(syscall6(0x8000000000000000ULL) != 0x80010003) {				
			if (strcmp(FirmwareVersion, "03.4100")==0){					
				syscall7(0x80000000000505d0ULL, 0xE92296887C0802A6ULL); 	
			}
		}
	}
}

#endif /* __PATCHES_H */
