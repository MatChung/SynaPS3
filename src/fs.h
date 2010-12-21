///////////////////////////////////////////////
///					fs.h	 				///
///		Filesystem related functions.		///
///////////////////////////////////////////////
#ifndef __FS_H
#define __FS_H

#include <cell/cell_fs.h> 

void mkdir(char* newDir) {
	cellFsMkdir(newDir, CELL_FS_DEFAULT_CREATE_MODE_1);
}

char fsStat(char* filename) {
	CellFsStat sb;
	return cellFsStat(filename, &sb) == CELL_FS_SUCCEEDED;
}

#endif /* __FS_H */