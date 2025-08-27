#include <fuzzer/FuzzedDataProvider.h>
#include <system/audio_effects/audio_effects_utils.h>
#include <utils/Errors.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <algorithm>

using android::effect::utils::EffectParamReader;

// Helper to dispatch read calls for different types.
// A static buffer is used as the destination for read operations to avoid
// repeated heap allocations or stack overflows within the fuzzer.
template <typename T>
void perform_read(EffectParamReader& reader, FuzzedDataProvider& provider) {
    static uint8_t buffer[4096];

    // Allow the fuzzer to choose 'n' across the full range of size_t.
    // A large 'n' can cause an integer overflow in the calculation `n * sizeof(T)`,
    // which is the primary vulnerability pattern we are targeting. An overflow can
    // bypass the boundary checks inside readFromValue and lead to an out-of-bounds read.
    const size_t n = provider.ConsumeIntegral<size_t>();

    // The destination buffer's size is not known by readFromValue. We pass the
    // fuzzer-controlled 'n' to test the function's internal size validation logic.
    // If the validation is bypassed due to an overflow, the subsequent memcpy may
    // write out of bounds of our static buffer, leading to a crash that identifies the bug.
    reader.readFromValue(reinterpret_cast<T*>(buffer), n);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider provider(data, size);

    // Let the fuzzer control psize. A larger range allows the initial read offset
    // (mValueROffset) to be large, which is a key component for triggering
    // integer overflows in boundary checks (offset + length).
    const uint32_t psize = provider.ConsumeIntegralInRange<uint32_t>(0, 65536);

    // The rest of the data will be used for the value part.
    std::vector<uint8_t> value_data = provider.ConsumeRemainingBytes<uint8_t>();
    const uint32_t vsize = value_data.size();

    // Replicate the implementation's padding logic.
    const size_t padded_psize =
            (psize == 0) ? 0 : (((psize - 1) / sizeof(int32_t) + 1) * sizeof(int32_t));
    const size_t total_data_size = padded_psize + vsize;

    // Allocate memory for effect_param_t and the data.
    std::vector<uint8_t> param_buffer(sizeof(effect_param_t) + total_data_size);
    effect_param_t* param = reinterpret_cast<effect_param_t*>(param_buffer.data());

    // Initialize the effect_param_t structure.
    param->psize = psize;
    param->vsize = vsize;

    // Place the fuzzer-controlled data into the 'value' section of the buffer.
    if (vsize > 0) {
        memcpy(param->data + padded_psize, value_data.data(), vsize);
    }

    EffectParamReader reader(*param);

    // Use the fuzzer data to drive a sequence of read operations.
    // This tests the stateful nature of the reader (advancing offsets), which is
    // crucial for getting the internal offset into a state where adding a large
    // length can cause a wraparound.
    while (provider.remaining_bytes() > 0) {
        // Use a dispatcher to test different template instantiations, including a wider
        // range of integer types to vary the sizeof(T) multiplier.
        typedef void (*ReadFunction)(EffectParamReader&, FuzzedDataProvider&);
        const ReadFunction funcs[] = {
                perform_read<uint8_t>,  perform_read<int8_t>,
                perform_read<uint16_t>, perform_read<int16_t>,
                perform_read<uint32_t>, perform_read<int32_t>,
                perform_read<uint64_t>, perform_read<int64_t>,
                perform_read<float>,    perform_read<double>,
        };
        // Pick a random read function to execute
        provider.PickValueInArray(funcs)(reader, provider);
    }

    return 0;
}
