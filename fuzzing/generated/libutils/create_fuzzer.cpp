#include <stddef.h>
#include <stdint.h>

#include <cutils/native_handle.h>
#include <utils/NativeHandle.h>

#include <fuzzer/FuzzedDataProvider.h>

// Fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    native_handle_t* handle = nullptr;

    // 25% of the time, test the nullptr handle case directly.
    if (fdp.ConsumeBool()) {
        bool ownsHandle = fdp.ConsumeBool();
        android::sp<android::NativeHandle> nativeHandle = android::NativeHandle::create(nullptr, ownsHandle);
        return 0;
    }

    // === Setup: Create and populate native_handle_t ===
    // Based on usage analysis, the most common case is 1 FD and 0 ints.
    // We will generate this specific case frequently, but also allow for broader fuzzing.
    int numFds = 0;
    int numInts = 0;
    if (fdp.ConsumeBool()) {
        // Common case: wrapping a single file descriptor.
        numFds = 1;
        numInts = 0;
    } else {
        // General case: fuzz the number of FDs and ints within a reasonable limit
        // to avoid excessive memory allocation.
        numFds = fdp.ConsumeIntegralInRange<int>(0, 128);
        numInts = fdp.ConsumeIntegralInRange<int>(0, 128);
    }

    handle = native_handle_create(numFds, numInts);

    // Error Handling: native_handle_create can fail if memory allocation fails.
    if (handle == nullptr) {
        return 0;
    }

    // === Parameter Parsing: Populate the handle's data ===
    // Fill the data array with fuzzed values. The first numFds are treated as
    // file descriptors, so we include potentially interesting values like -1.
    for (int i = 0; i < numFds; ++i) {
        handle->data[i] = fdp.PickValueInArray<int>({-1, 0, 1, 2, fdp.ConsumeIntegral<int>()});
    }
    for (int i = 0; i < numInts; ++i) {
        handle->data[numFds + i] = fdp.ConsumeIntegral<int>();
    }

    // Security Focus: Test for robustness against corrupted metadata.
    // Occasionally mismatch the handle's metadata with its actual allocated size.
    if (fdp.ConsumeBool()) {
        handle->numFds = fdp.ConsumeIntegralInRange<int>(0, 256);
        handle->numInts = fdp.ConsumeIntegralInRange<int>(0, 256);
    }

    // The 'ownsHandle' parameter is critical for memory safety testing.
    bool ownsHandle = fdp.ConsumeBool();

    // === Target Invocation ===
    // Call the target function with the constructed handle.
    android::sp<android::NativeHandle> nativeHandle = android::NativeHandle::create(handle, ownsHandle);

    // === Cleanup: Manage resources based on ownership ===
    // This logic is crucial. If the created NativeHandle does NOT take ownership,
    // we are responsible for closing and deleting the original native_handle_t.
    // If it DOES take ownership, the sp<> destructor will handle it, and we must not.
    // Incorrectly handling this can lead to double-frees or memory leaks.
    if (!ownsHandle) {
        native_handle_close(handle);
        native_handle_delete(handle);
    }

    return 0;
}
