///////////////////////////////////////////////
///				SynaPS3lib 					///
///	          by n4ru && methionine_		///
/// 	Compatible with Sony PS3 SDK 3.41	///
///////////////////////////////////////////////
///					payload.h				///
///	Functions related to dongle payloads.	///
///////////////////////////////////////////////
#ifndef __PAYLOAD_H
#define __PAYLOAD_H

#include "system.h"

#define PAYLOAD_CAPS_SYSCALL36	1
#define PAYLOAD_CAPS_SYSCALL8	2
#define PAYLOAD_CAPS_PEEKPOKE	4
#define PAYLOAD_CAPS_SYSCALL35	8

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

unsigned char GetPayloadName() {
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
    if (ret == 13)
		return 5;
    if (ret == 8)
		return 4;
    if (ret == 7)
		return 3;
    if (ret == 5)
		return 2;
    if (ret == 1)
		return 1;
	return 0;
}

#endif /* __PAYLOAD_H */
