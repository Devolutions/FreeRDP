#ifndef CS_HEADLESS_H_
#define CS_HEADLESS_H_

#include <freerdp/api.h>

FREERDP_API BOOL csharp_create_shared_buffer(char* name, int size);
FREERDP_API void csharp_destroy_shared_buffer(char* name);

#endif /* CS_HEADLESS_H_ */