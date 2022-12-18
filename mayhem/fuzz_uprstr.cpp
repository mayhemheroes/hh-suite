#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "util.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    int src_width = provider.ConsumeIntegralInRange<int>(0, INT_MAX);

    char* str = strdup(provider.ConsumeRandomLengthString().c_str());
    uprstr(str);
    free(str);
    return 0;
}
