#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <cstring>
#include <algorithm>
#include <functional>

#include <audio_utils/channels.h>

// The non-destructive functions use a variable-length array (VLA) on the stack,
// which can cause stack exhaustion. We limit the number of frames to prevent the
// fuzzer from trivially hitting this limit, allowing it to find other bugs.
constexpr size_t kMaxFuzzerFrames = 4096;

// Defines the relationship between input and output channels to systematically
// target different code paths (expansion, contraction, mono/stereo conversions).
enum class ChannelRelationship {
    kExpand,
    kContract,
    kEqual,
    kMonoToMulti,
    kMultiToMono,
    kMaxValue = kMultiToMono,
};

// A type alias for the function signature of the APIs being tested.
using AdjustChannelsApi = std::function<size_t(
    const void*, size_t, void*, size_t, unsigned, size_t)>;

void TestApi(const AdjustChannelsApi& api, const void* in_buff, size_t in_buff_chans,
             size_t out_buff_chans, unsigned sample_size_in_bytes, size_t num_in_bytes,
             size_t out_buff_size) {
    // Test out-of-place conversion.
    {
        std::vector<uint8_t> out_buff_vec(out_buff_size);
        api(in_buff, in_buff_chans, out_buff_vec.data(), out_buff_chans,
            sample_size_in_bytes, num_in_bytes);
    }

    // Test in-place conversion.
    {
        const size_t in_place_buff_size = std::max(num_in_bytes, out_buff_size);
        std::vector<uint8_t> in_place_buff(in_place_buff_size);
        if (num_in_bytes > 0) {
            memcpy(in_place_buff.data(), in_buff, num_in_bytes);
        }
        api(in_place_buff.data(), in_buff_chans, in_place_buff.data(),
            out_buff_chans, sample_size_in_bytes, num_in_bytes);
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    const unsigned sample_sizes[] = {1, 2, 3, 4};
    const unsigned sample_size_in_bytes = fdp.PickValueInArray(sample_sizes);

    size_t in_buff_chans = 0;
    size_t out_buff_chans = 0;

    // Systematically select channel relationships to ensure all major code paths are tested.
    auto channel_relationship = fdp.PickValueInArray<ChannelRelationship>(
        {ChannelRelationship::kExpand, ChannelRelationship::kContract,
         ChannelRelationship::kEqual, ChannelRelationship::kMonoToMulti,
         ChannelRelationship::kMultiToMono});

    switch (channel_relationship) {
        case ChannelRelationship::kExpand:
            in_buff_chans = fdp.ConsumeIntegralInRange<size_t>(1, 16);
            out_buff_chans = fdp.ConsumeIntegralInRange<size_t>(in_buff_chans + 1, 32);
            break;
        case ChannelRelationship::kContract:
            out_buff_chans = fdp.ConsumeIntegralInRange<size_t>(1, 16);
            in_buff_chans = fdp.ConsumeIntegralInRange<size_t>(out_buff_chans + 1, 32);
            break;
        case ChannelRelationship::kEqual:
            in_buff_chans = fdp.ConsumeIntegralInRange<size_t>(1, 32);
            out_buff_chans = in_buff_chans;
            break;
        case ChannelRelationship::kMonoToMulti:
            in_buff_chans = 1;
            out_buff_chans = fdp.ConsumeIntegralInRange<size_t>(2, 32);
            break;
        case ChannelRelationship::kMultiToMono:
            in_buff_chans = fdp.ConsumeIntegralInRange<size_t>(2, 32);
            out_buff_chans = 1;
            break;
    }

    std::vector<uint8_t> in_data = fdp.ConsumeRemainingBytes<uint8_t>();

    const size_t in_frame_size = in_buff_chans * sample_size_in_bytes;
    if (in_frame_size == 0) {
        return 0;
    }

    // Ensure the input data is a multiple of the frame size.
    const size_t num_in_bytes = (in_data.size() / in_frame_size) * in_frame_size;
    if (num_in_bytes == 0) {
        return 0;
    }
    const void* in_buff = in_data.data();

    const size_t num_frames = num_in_bytes / in_frame_size;
    if (num_frames > kMaxFuzzerFrames) {
        return 0;
    }

    const size_t out_frame_size = out_buff_chans * sample_size_in_bytes;
    const size_t out_buff_size = num_frames * out_frame_size;

    // Test all three APIs with the same generated data to maximize coverage per input.
    TestApi(adjust_channels, in_buff, in_buff_chans, out_buff_chans,
            sample_size_in_bytes, num_in_bytes, out_buff_size);
    TestApi(adjust_selected_channels, in_buff, in_buff_chans, out_buff_chans,
            sample_size_in_bytes, num_in_bytes, out_buff_size);
    TestApi(adjust_channels_non_destructive, in_buff, in_buff_chans, out_buff_chans,
            sample_size_in_bytes, num_in_bytes, out_buff_size);

    return 0;
}
