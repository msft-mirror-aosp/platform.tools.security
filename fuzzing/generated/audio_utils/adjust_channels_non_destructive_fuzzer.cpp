#include <audio_utils/channels.h>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

// The target function uses a stack-based VLA. Cap the input size to a small
// value to avoid trivial stack exhaustion and focus on logic bugs within the
// channel adjustment algorithms. 4KB is a safe and reasonable limit.
constexpr size_t kMaxBufferSize = 4 * 1024;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);

  // Define valid sample sizes.
  const unsigned kSampleSizes[] = {1, 2, 3, 4};
  const unsigned sample_size_in_bytes = fdp.PickValueInArray(kSampleSizes);

  // To ensure both expansion and contraction paths are tested, we explicitly
  // decide which scenario to fuzz.
  size_t in_buff_chans = 0;
  size_t out_buff_chans = 0;
  constexpr size_t kMinChans = 1;
  constexpr size_t kMaxChans = 32;

  if (fdp.ConsumeBool()) {
    // Fuzz expansion path (out_buff_chans > in_buff_chans)
    in_buff_chans = fdp.ConsumeIntegralInRange<size_t>(kMinChans, kMaxChans - 1);
    out_buff_chans = fdp.ConsumeIntegralInRange<size_t>(in_buff_chans + 1, kMaxChans);
  } else {
    // Fuzz contraction path (out_buff_chans < in_buff_chans)
    out_buff_chans = fdp.ConsumeIntegralInRange<size_t>(kMinChans, kMaxChans - 1);
    in_buff_chans = fdp.ConsumeIntegralInRange<size_t>(out_buff_chans + 1, kMaxChans);
  }

  // Calculate input frame size and ensure it's valid.
  const size_t in_frame_size = in_buff_chans * sample_size_in_bytes;
  if (in_frame_size == 0) {
    return 0;
  }

  // The non-destructive functions require input and output buffers to be the
  // same size. We consume the remaining fuzzer data for our buffer.
  std::vector<uint8_t> buffer_data = fdp.ConsumeRemainingBytes<uint8_t>();
  size_t num_in_bytes = buffer_data.size();

  // Cap the buffer size and align it to a full input frame, which is a
  // precondition of the underlying macros.
  if (num_in_bytes > kMaxBufferSize) {
    num_in_bytes = kMaxBufferSize;
  }
  const size_t num_frames = num_in_bytes / in_frame_size;
  if (num_frames == 0) {
    return 0;
  }
  num_in_bytes = num_frames * in_frame_size;
  buffer_data.resize(num_in_bytes);

  // Decide whether to test in-place or with separate buffers.
  if (fdp.ConsumeBool()) {
    // Test the in-place scenario where in_buff and out_buff point to the same memory.
    adjust_channels_non_destructive(buffer_data.data(), in_buff_chans,
                                    buffer_data.data(), out_buff_chans,
                                    sample_size_in_bytes, num_in_bytes);
  } else {
    // Test with separate, but equally-sized, input and output buffers.
    std::vector<uint8_t> out_buff(num_in_bytes);
    adjust_channels_non_destructive(buffer_data.data(), in_buff_chans,
                                    out_buff.data(), out_buff_chans,
                                    sample_size_in_bytes, num_in_bytes);
  }

  return 0;
}
