#ifndef CDSE_HERRADURA_COMPAT_H
#define CDSE_HERRADURA_COMPAT_H

#include <herradura.h>

/* Historical headers have no width field; current headers require BA_INIT. */
#ifndef BA_INIT
#define BA_INIT {{0}}
#endif

#endif
