
#include "DevolutionsRdp.h"

#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#endif

#include <sys/stat.h>
#include <fcntl.h>

BOOL csharp_create_shared_buffer(char* name, int size)
{
	BOOL result = FALSE;

#if !defined(ANDROID) && !defined(IOS) && !defined(_WIN32)
	int desc = shm_open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
	
	if(desc < 0)
		return NULL;
	
	if (ftruncate(desc, size) == 0)
		result = TRUE;
		//handle = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, desc, 0);
	
	close(desc);
#endif
	
	return result;
}

void csharp_destroy_shared_buffer(char* name)
{
#if !defined(ANDROID) && !defined(IOS) && !defined(_WIN32)
	//munmap(buffer, size);
	shm_unlink(name);
#endif
}
