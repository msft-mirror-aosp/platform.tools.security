#include <fuzzer/FuzzedDataProvider.h>
#include "lodepng.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider stream(data, size);

    // Create fuzzed input
    std::vector<uint8_t> fuzzedInput = stream.ConsumeRemainingBytes<uint8_t>();

    // Decompression settings (could be fuzzed as well)
    LodePNGDecompressSettings settings;
    lodepng_decompress_settings_init(&settings);

    // Prepare output parameters
    unsigned char *out = nullptr;
    size_t outsize = 0;

    // Call the function under test
    lodepng_zlib_decompress(&out, &outsize, fuzzedInput.data(), fuzzedInput.size(), &settings);

    // Clean up
    free(out);

    return 0;
}
