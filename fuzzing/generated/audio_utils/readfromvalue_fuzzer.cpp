#include <fuzzer/FuzzedDataProvider.h>
#include <vector>
#include <cstdint>

// For EffectParamReader
#include "system/audio_effects/audio_effects_utils.h"
// For effect_param_t
#include "system/audio_effect.h"
// For status_t, OK
#include "utils/Errors.h"

using android::effect::utils::EffectParamReader;

// This is the entry point for the libFuzzer engine.
// It takes a buffer of fuzzer-generated data and its size.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider provider(data, size);

    // --- Setup Code ---
    // 1. Generate the effect_param_t structure and its data buffer.
    // We consume a variable-sized chunk of the fuzz data to represent the entire
    // effect_param_t structure, including its flexible data array. This allows
    // the fuzzer to directly manipulate psize, vsize, and the data content.
    std::vector<uint8_t> param_buffer = provider.ConsumeBytes<uint8_t>(
        provider.ConsumeIntegralInRange<size_t>(0, 4096));

    // The buffer must be at least large enough to hold the effect_param_t header.
    if (param_buffer.size() < sizeof(effect_param_t)) {
        return 0;
    }
    effect_param_t* param = reinterpret_cast<effect_param_t*>(param_buffer.data());

    // 2. Instantiate the EffectParamReader with the fuzzer-generated parameter struct.
    // The reader's internal state (like the initial read offset) is determined by
    // the psize and vsize fields within the 'param' structure.
    EffectParamReader reader(*param);

    // --- Fuzzing Loop: Target Invocation ---
    // Emulate real-world usage by performing a series of sequential reads.
    // This tests the stateful nature of the reader, specifically how the internal
    // read offset (mValueROffset) is advanced after each successful read.
    while (provider.remaining_bytes() > 0) {
        // Use the provider to decide which type of data to read and how many elements.
        uint8_t type_selector = provider.ConsumeIntegral<uint8_t>();
        size_t n = provider.ConsumeIntegralInRange<size_t>(0, 128);

        // It's valid to read 0 elements, so we don't skip it.

        switch (type_selector % 7) {
            case 0: {
                std::vector<uint8_t> read_buffer(n);
                reader.readFromValue(read_buffer.data(), n);
                break;
            }
            case 1: {
                std::vector<int8_t> read_buffer(n);
                reader.readFromValue(read_buffer.data(), n);
                break;
            }
            case 2: {
                std::vector<uint16_t> read_buffer(n);
                reader.readFromValue(read_buffer.data(), n);
                break;
            }
            case 3: {
                std::vector<int32_t> read_buffer(n);
                reader.readFromValue(read_buffer.data(), n);
                break;
            }
            case 4: {
                std::vector<int64_t> read_buffer(n);
                reader.readFromValue(read_buffer.data(), n);
                break;
            }
            case 5: {
                std::vector<float> read_buffer(n);
                reader.readFromValue(read_buffer.data(), n);
                break;
            }
            case 6: {
                std::vector<double> read_buffer(n);
                reader.readFromValue(read_buffer.data(), n);
                break;
            }
        }
    }

    return 0;
}