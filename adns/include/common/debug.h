
#ifndef _ADNS_DEBUG_H_
#define _ADNS_DEBUG_H_

#include <stdio.h>

#define ADNS_PRINT_DEBUG 1

#ifdef ADNS_PRINT_DEBUG
/*lint -emacro( {717}, dbgPrintf ) */
#define dbg_printf( ... )	do { printf(__VA_ARGS__); fflush(stdout); } while((0))
#else
#define dbg_printf( ... ) 	do { } while((0))
#endif

#endif

