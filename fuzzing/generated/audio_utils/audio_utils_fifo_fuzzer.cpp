#include <audio_utils/fifo.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <vector>
#include <climits>

// Define reasonable max values to avoid out-of-memory errors.
constexpr size_t kMaxFrameCount = 4096;
constexpr size_t kMaxFrameSize = 4096;

// Generates a size_t value for read/write counts, including edge cases.
static size_t generate_fuzzed_count(FuzzedDataProvider& fdp, uint32_t frameCount) {
    switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 5)) {
        case 0: return 0;
        case 1: return 1;
        case 2: return frameCount;
        case 3: return fdp.ConsumeIntegralInRange<size_t>(0, frameCount);
        case 4: return fdp.ConsumeIntegralInRange<size_t>(0, frameCount * 2); // Test larger counts
        case 5: return fdp.ConsumeIntegral<uint32_t>(); // Test extreme values
    }
    return 0; // Should not be reached
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    uint32_t frameCount = fdp.ConsumeIntegralInRange<uint32_t>(1, kMaxFrameCount);
    uint32_t frameSize = fdp.ConsumeIntegralInRange<uint32_t>(1, kMaxFrameSize);

    // The implementation checks: frameCount > ((uint32_t) INT32_MAX) / frameSize
    // Replicate this check to avoid a LOG_ALWAYS_FATAL.
    if (static_cast<uint64_t>(frameCount) * frameSize > INT32_MAX) {
        return 0;
    }

    size_t bufferSize = static_cast<size_t>(frameCount) * frameSize;
    std::vector<uint8_t> buffer(bufferSize);

    bool throttlesWriter = fdp.ConsumeBool();
    // The single-process constructor being fuzzed here fatally aborts if sync is SHARED.
    audio_utils_fifo_sync sync = fdp.PickValueInArray({
        AUDIO_UTILS_FIFO_SYNC_PRIVATE,
        AUDIO_UTILS_FIFO_SYNC_SLEEP,
        AUDIO_UTILS_FIFO_SYNC_SINGLE_THREADED,
    });

    audio_utils_fifo fifo(frameCount, frameSize, buffer.data(), throttlesWriter, sync);
    audio_utils_fifo_writer writer(fifo);
    // Fuzz the 'flush' parameter in the reader's constructor.
    audio_utils_fifo_reader reader(fifo, throttlesWriter, fdp.ConsumeBool());

    while (fdp.remaining_bytes() > 2) {
        switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 11)) {
            case 0: { // Write data to the FIFO.
                size_t count = generate_fuzzed_count(fdp, frameCount);
                if (count > kMaxFrameCount) count = kMaxFrameCount; // Avoid OOM
                std::vector<uint8_t> writeBuffer = fdp.ConsumeBytes<uint8_t>(count * frameSize);
                if (writeBuffer.size() == count * frameSize) {
                    writer.write(writeBuffer.data(), count);
                }
                break;
            }
            case 1: { // Read data from the FIFO.
                size_t count = generate_fuzzed_count(fdp, frameCount);
                if (count > kMaxFrameCount) count = kMaxFrameCount; // Avoid OOM
                std::vector<uint8_t> readBuffer(count * frameSize);
                if (!readBuffer.empty()) {
                    reader.read(readBuffer.data(), count);
                }
                break;
            }
            case 2: { // Resize the writer's effective frame count.
                uint32_t newSize;
                switch (fdp.ConsumeIntegralInRange<uint8_t>(0, 5)) {
                    case 0: newSize = 0; break;
                    case 1: newSize = 1; break;
                    case 2: newSize = frameCount; break;
                    case 3: newSize = frameCount + 1; break;
                    case 4: newSize = fdp.ConsumeIntegralInRange<uint32_t>(0, frameCount * 2); break;
                    case 5: newSize = fdp.ConsumeIntegral<uint32_t>(); break;
                }
                writer.resize(newSize);
                break;
            }
            case 3: { // Configure writer hysteresis levels.
                uint32_t arm = fdp.ConsumeIntegral<uint32_t>();
                uint32_t trigger = fdp.ConsumeIntegral<uint32_t>();
                writer.setHysteresis(arm, trigger);
                break;
            }
            case 4: { // Configure reader hysteresis levels.
                int32_t arm = fdp.ConsumeIntegral<int32_t>();
                uint32_t trigger = fdp.ConsumeIntegral<uint32_t>();
                reader.setHysteresis(arm, trigger);
                break;
            }
            case 5: { // Flush the reader.
                size_t lost = 0;
                reader.flush(&lost);
                break;
            }
            case 6: { // Check available frames for writing.
                writer.available();
                break;
            }
            case 7: { // Check available frames for reading.
                size_t lost = 0;
                reader.available(&lost);
                break;
            }
            case 8: { // Test writer obtain/release cycle.
                audio_utils_iovec iovec[2];
                size_t obtainCount = generate_fuzzed_count(fdp, frameCount);
                if (obtainCount > kMaxFrameCount) obtainCount = kMaxFrameCount;
                ssize_t obtained = writer.obtain(iovec, obtainCount, nullptr);
                if (obtained > 0) {
                    // Release a count that may or may not match what was obtained.
                    size_t releaseCount = generate_fuzzed_count(fdp, obtained);
                    writer.release(releaseCount);
                }
                break;
            }
            case 9: { // Test reader obtain/release cycle.
                audio_utils_iovec iovec[2];
                size_t obtainCount = generate_fuzzed_count(fdp, frameCount);
                if (obtainCount > kMaxFrameCount) obtainCount = kMaxFrameCount;
                ssize_t obtained = reader.obtain(iovec, obtainCount, nullptr);
                if (obtained > 0) {
                    // Release a count that may or may not match what was obtained.
                    size_t releaseCount = generate_fuzzed_count(fdp, obtained);
                    reader.release(releaseCount);
                }
                break;
            }
            case 10: { // Get writer hysteresis levels.
                uint32_t arm, trigger;
                writer.getHysteresis(&arm, &trigger);
                break;
            }
            case 11: { // Get reader hysteresis levels.
                int32_t arm;
                uint32_t trigger;
                reader.getHysteresis(&arm, &trigger);
                break;
            }
        }
    }

    return 0;
}
