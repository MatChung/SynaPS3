///////////////////////////////////////////////
///			SynaPS3lib 2011 (c) n4ru		///
///////////////////////////////////////////////
///					pad.h					///
///		Controller and gamepad functions.	///
///////////////////////////////////////////////
#ifndef __PAD_H
#define __PAD_H

#include <cell/pad.h>

#define	BUTTON_SELECT		(1<<0)
#define	BUTTON_L3			(1<<1)
#define	BUTTON_R3			(1<<2)
#define	BUTTON_START		(1<<3)
#define	BUTTON_UP			(1<<4)
#define	BUTTON_RIGHT		(1<<5)
#define	BUTTON_DOWN			(1<<6)
#define	BUTTON_LEFT			(1<<7)
#define	BUTTON_L2			(1<<8)
#define	BUTTON_R2			(1<<9)
#define	BUTTON_L1			(1<<10)
#define	BUTTON_R1			(1<<11)
#define	BUTTON_TRIANGLE		(1<<12)
#define	BUTTON_CIRCLE		(1<<13)
#define	BUTTON_CROSS		(1<<14)
#define	BUTTON_SQUARE		(1<<15)

static unsigned cmd_pad= 0;

static uint32_t new_pad=0,old_pad=0;

static int pad_read(void) {
	int ret;
	uint32_t	padd;
	CellPadData databuf;
	CellPadInfo infobuf;
	static uint32_t old_info = 0;
	cmd_pad= 0;
	ret = cellPadGetInfo(&infobuf);
	if (ret != 0) {
		old_pad=new_pad = 0;
		return 1;
	}
	if (infobuf.status[0] == CELL_PAD_STATUS_DISCONNECTED) {
		old_pad=new_pad = 0;
		return 1;
	}
	if((infobuf.info & CELL_PAD_INFO_INTERCEPTED) && (!(old_info & CELL_PAD_INFO_INTERCEPTED)))	{
		old_info = infobuf.info;
	} else if((!(infobuf.info & CELL_PAD_INFO_INTERCEPTED)) && (old_info & CELL_PAD_INFO_INTERCEPTED)) {
			old_info = infobuf.info;
			old_pad=new_pad = 0;
			return 1;
	}
	ret = cellPadGetData(0, &databuf);
	if (ret != CELL_PAD_OK) {
		old_pad=new_pad = 0;
		return 1;
	}
	if (databuf.len == 0) {
		new_pad = 0;
		return 1;
	}
	padd = (databuf.button[2]|(databuf.button[3] << 8));
	new_pad=padd & (~old_pad);
	old_pad=padd;
	return 1;
	
}

#endif /* __PAD_H */
