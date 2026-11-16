#ifndef CME_CONTEXT_COLUMN_INTERNAL_H
#define CME_CONTEXT_COLUMN_INTERNAL_H

/* Private representation shared by the staging and container codecs. */
struct cmeContextColumnStage
{
    size_t count;
    cmeContextColumnCell *cells;
};
#endif
