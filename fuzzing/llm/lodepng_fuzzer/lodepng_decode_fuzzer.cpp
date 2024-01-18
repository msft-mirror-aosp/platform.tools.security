#include <fuzzer/FuzzedDataProvider.h>
#include "lodepng.h"  // Adjust the include path as necessary

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider stream(data, size);

    // Create fuzzed inputs
    std::vector<uint8_t> fuzzedInput = stream.ConsumeRemainingBytes<uint8_t>();
    LodePNGState state;
    lodepng_state_init(&state);

    // Prepare output parameters
    unsigned char *out = nullptr;
    unsigned w = 0, h = 0;

    // Call the function under test
    lodepng_decode(&out, &w, &h, &state, fuzzedInput.data(), fuzzedInput.size());

    // Clean up
    free(out);
    lodepng_state_cleanup(&state);

    return 0;
}
