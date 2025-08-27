#include <audio_utils/fifo.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <climits>

// Constants to avoid excessive memory allocation and keep the fuzzer efficient.
constexpr size_t kMaxFrameCount = 4096;
constexpr size_t kMaxFrameSize = 256;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Fuzz FIFO parameters. To better exercise the mFudgeFactor logic, which depends on
    // whether frameCount is a power of two, we'll explicitly choose interesting values.
    uint32_t frameCount;
    if (fdp.ConsumeBool()) {
        constexpr uint32_t interestingFrameCounts[] = {
            1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33,
            1023, 1024, 1025, kMaxFrameCount - 1, kMaxFrameCount
        };
        frameCount = fdp.PickValueInArray(interestingFrameCounts);
    } else {
        frameCount = fdp.ConsumeIntegralInRange<uint32_t>(1, kMaxFrameCount);
    }
    const uint32_t frameSize = fdp.ConsumeIntegralInRange<uint32_t>(1, kMaxFrameSize);

    // Avoid fatal error from frameCount > (INT32_MAX / frameSize)
    if (static_cast<uint64_t>(frameCount) * frameSize > INT32_MAX) {
        return 0;
    }

    std::vector<uint8_t> fifo_buffer(frameCount * frameSize);
    // Enable throttling to test more complex code paths involving writer/reader interaction.
    audio_utils_fifo fifo(frameCount, frameSize, fifo_buffer.data(), true /* throttlesWriter */);
    audio_utils_fifo_writer writer(fifo);
    audio_utils_fifo_reader reader(fifo, true /* throttlesWriter */);

    // Perform a sequence of actions to simulate real-world usage and explore state.
    while (fdp.remaining_bytes() > 0) {
        switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 5)) {
            case 0: { // Action: Write data to the FIFO
                const size_t count = fdp.ConsumeIntegralInRange<size_t>(0, frameCount * 2);
                const size_t bytes_to_write = count * frameSize;
                std::vector<uint8_t> write_buffer = fdp.ConsumeBytes<uint8_t>(bytes_to_write);

                // The write call requires a buffer of at least `count * frameSize` bytes.
                if (write_buffer.size() != bytes_to_write) {
                    break;
                }

                if (fdp.ConsumeBool()) {
                    struct timespec timeout;
                    if (fdp.ConsumeBool()) {
                        // Target special case identified in source code.
                        timeout.tv_sec = LONG_MAX;
                        timeout.tv_nsec = 0;
                    } else {
                        timeout.tv_sec = fdp.ConsumeIntegralInRange<long>(0, 1);
                        timeout.tv_nsec = fdp.ConsumeIntegralInRange<long>(0, 999999999);
                    }
                    writer.write(write_buffer.data(), count, &timeout);
                } else {
                    writer.write(write_buffer.data(), count, nullptr);
                }
                break;
            }
            case 1: { // Action: Read data from the FIFO to free up space
                const size_t count = fdp.ConsumeIntegralInRange<size_t>(0, frameCount * 2);
                std::vector<uint8_t> read_buffer(count * frameSize);
                reader.read(read_buffer.data(), count);
                break;
            }
            case 2: { // Action: Resize the writer's effective frame count
                uint32_t new_size = fdp.ConsumeIntegralInRange<uint32_t>(0, frameCount + 1);
                writer.resize(new_size);
                break;
            }
            case 3: { // Action: Set writer hysteresis levels
                uint32_t arm = fdp.ConsumeIntegralInRange<uint32_t>(0, frameCount + 1);
                uint32_t trigger = fdp.ConsumeIntegralInRange<uint32_t>(0, frameCount + 1);
                writer.setHysteresis(arm, trigger);
                break;
            }
            case 4: { // Action: Check available space for writing
                writer.available();
                break;
            }
            case 5: { // Action: Granular obtain/release to test state management
                const size_t count_to_obtain = fdp.ConsumeIntegralInRange<size_t>(0, frameCount * 2);
                audio_utils_iovec iovec[2];
                ssize_t obtained = writer.obtain(iovec, count_to_obtain, nullptr);
                if (obtained > 0) {
                    // Fuzz the release count to be different from obtained count
                    // to test error handling paths (e.g., release more than obtained).
                    size_t count_to_release = fdp.ConsumeIntegralInRange<size_t>(0, obtained * 2);
                    writer.release(count_to_release);
                }
                break;
            }
        }
    }

    return 0;
}
