
// Fuzz harness for adjust_channels_non_destructive
// This harness is designed to find memory corruption vulnerabilities in the
// core channel adjustment logic.

#include <fuzzer/FuzzedDataProvider.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

// For adjust_channels_non_destructive
#include <audio_utils/channels.h>

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider provider(data, size);

  // --- Parameter Parsing and Setup ---

  // 1. Generate `sample_size_in_bytes`.
  // The target function has a switch statement on this value. We must use one
  // of the supported sizes to hit the core logic.
  const unsigned sample_size_in_bytes =
      provider.PickValueInArray<unsigned>({1, 2, 3, 4});

  // 2. Generate input and output channel counts.
  // These must be greater than zero to avoid division-by-zero when calculating
  // frame sizes. A practical upper limit is chosen to prevent path explosion
  // while still covering many realistic audio configurations (mono, stereo, 5.1,
  // 7.1, etc.).
  const size_t in_buff_chans = provider.ConsumeIntegralInRange<size_t>(1, 16);
  const size_t out_buff_chans = provider.ConsumeIntegralInRange<size_t>(1, 16);

  // 3. Generate a realistic number of audio frames.
  // This determines the overall size of the audio buffers.
  const size_t num_frames = provider.ConsumeIntegralInRange<size_t>(0, 1024);

  // --- Buffer Allocation and Initialization ---

  // 4. Calculate the total buffer size required.
  // For non-destructive operations, the input and output buffers must be large
  // enough to hold the data from the configuration with the maximum number of
  // channels.
  const size_t max_chans = std::max(in_buff_chans, out_buff_chans);
  const size_t single_frame_size_bytes = max_chans * sample_size_in_bytes;
  size_t total_buffer_size = num_frames * single_frame_size_bytes;

  // 5. Perform safety checks to prevent excessive memory allocation.
  // Check for integer overflow during buffer size calculation.
  if (num_frames > 0 &&
      (total_buffer_size / num_frames) != single_frame_size_bytes) {
    return 0; // Overflow occurred, exit.
  }

  // 6. Allocate and fill buffers.
  // The input buffer is filled with data from the fuzzer.
  std::vector<uint8_t> buffer1 =
      provider.ConsumeBytes<uint8_t>(total_buffer_size);
  if (buffer1.size() != total_buffer_size) {
    // Not enough data to fill the buffer, exit.
    return 0;
  }
  // A second buffer is allocated for out-of-place operations.
  std::vector<uint8_t> buffer2(total_buffer_size);

  // 7. Randomly choose between in-place and out-of-place operations.
  // This is a key insight from the usage patterns, as the underlying macros
  // have different code paths for each case.
  void* in_buff = buffer1.data();
  void* out_buff = provider.ConsumeBool() ? buffer1.data() : buffer2.data();

  // --- Final Parameter Calculation ---

  // 8. Calculate `num_in_bytes`.
  // This parameter is critical. It must be a multiple of the input frame size.
  // As seen in the contexts, it represents the logical size of the input data,
  // which might be smaller than the total allocated buffer, especially during
  // channel expansion.
  const size_t in_frame_size = in_buff_chans * sample_size_in_bytes;
  const size_t num_in_bytes = num_frames * in_frame_size;

  // As a final safeguard, ensure the calculated input size does not exceed the
  // allocated buffer. This should not be triggered with the current logic.
  if (num_in_bytes > total_buffer_size) {
    return 0;
  }

  // --- Target Invocation ---

  // 9. Call the target function with the prepared parameters.
  // Sanitizers (ASan, UBSan) will detect memory corruption or undefined
  // behavior within this call.
  adjust_channels_non_destructive(in_buff, in_buff_chans, out_buff,
                                  out_buff_chans, sample_size_in_bytes,
                                  num_in_bytes);

  // --- Cleanup ---
  // All resources (`std::vector`) are automatically cleaned up by RAII.

  return 0;
}
