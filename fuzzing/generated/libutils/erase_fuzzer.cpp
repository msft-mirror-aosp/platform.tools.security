#include <fuzzer/FuzzedDataProvider.h>
#include <stddef.h>
#include <stdint.h>

#include <utils/SortedVector.h>

// Fuzzer entry point
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider provider(data, size);
    android::SortedVector<int32_t> vec;

    // 1. Setup Code: Populate the vector with a variable number of elements
    // This creates a valid and diverse state for the SortedVector object before
    // we call the target function. The number of elements is determined by the fuzzer.
    size_t num_elements_to_add = provider.ConsumeIntegralInRange<size_t>(0, 100);
    for (size_t i = 0; i < num_elements_to_add; ++i) {
        // Using add() is crucial to maintain the vector's sorted invariant.
        vec.add(provider.ConsumeIntegral<int32_t>());
    }

    // If the vector is empty, there's nothing to erase. We can exit early.
    if (vec.isEmpty()) {
        return 0;
    }

    // 2. Parameter Parsing & Edge Case Generation
    // The 'pos' parameter is an iterator (raw pointer), making it a critical
    // target for security testing. We will test valid, edge-case, and invalid pointers.
    android::SortedVector<int32_t>::iterator pos;

    // Use a fuzzer-driven switch to select different test cases for the iterator.
    // This ensures we consistently test for high-impact security vulnerabilities.
    enum class IteratorTestCase {
        kValid,
        kEnd,
        kBeginMinusOne,
        kEndPlusOne,
        kDanglingPointer,
        kMaxValue = kDanglingPointer
    };

    switch (provider.ConsumeEnum<IteratorTestCase>()) {
        case IteratorTestCase::kValid: {
            // Generate a random but valid index within the vector's bounds.
            size_t index = provider.ConsumeIntegralInRange<size_t>(0, vec.size() - 1);
            pos = vec.begin() + index;
            break;
        }
        case IteratorTestCase::kEnd: {
            // Test the common off-by-one error case by using the end() iterator.
            pos = vec.end();
            break;
        }
        case IteratorTestCase::kBeginMinusOne: {
            // Test out-of-bounds access before the vector's data.
            pos = vec.begin() - 1;
            break;
        }
        case IteratorTestCase::kEndPlusOne: {
            // Test out-of-bounds access after the vector's data.
            pos = vec.end() + 1;
            break;
        }
        case IteratorTestCase::kDanglingPointer: {
            // Test for use-after-free / dangling pointer vulnerabilities.
            // 1. Store an iterator.
            pos = vec.begin() + provider.ConsumeIntegralInRange<size_t>(0, vec.size() - 1);
            // 2. Perform operations that might reallocate the underlying buffer,
            //    invalidating the stored iterator.
            size_t num_realloc_elements = provider.ConsumeIntegralInRange<size_t>(1, 50);
            for (size_t i = 0; i < num_realloc_elements; ++i) {
                vec.add(provider.ConsumeIntegral<int32_t>());
            }
            // 3. The 'pos' iterator is now potentially dangling. Using it is unsafe.
            break;
        }
    }

    // 3. Target Invocation
    // Call the 'erase' function with the generated iterator.
    // This is the function we are fuzzing.
    vec.erase(pos);


    // 4. Cleanup: No explicit cleanup is needed.
    // The 'vec' object is stack-allocated, and its destructor will be
    // automatically called when the function exits, freeing any allocated memory.
    return 0;
}
