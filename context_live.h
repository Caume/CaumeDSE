#ifndef CME_CONTEXT_LIVE_H
#define CME_CONTEXT_LIVE_H

#include <stdint.h>
#include "context_crypto.h"

/* Call only after normal certificate and role checks. Returns an HTTP status. */
int cmeContextLiveRead(const char *org, const char *storage, const char *document, const char *orgKey,
    int64_t row, cmeContextV2Buffer *value);

#endif
