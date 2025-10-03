
// Fuzz harness for android::SortedVector::remove
#include <cstdint>
#include <cstddef>
#include <type_traits>
#include <fuzzer/FuzzedDataProvider.h>
#include <utils/SortedVector.h> // For SortedVector
#include <vector>
#include <algorithm>

// Define a custom struct for testing complex types, as recommended by the plan.
// This helps test the comparison logic within SortedVector more thoroughly.
struct FuzzableStruct {
    int a;
    char b;

    // Required for SortedVector to compare and sort elements.
    bool operator<(const FuzzableStruct& other) const {
        if (a != other.a) return a < other.a;
        return b < other.b;
    }

    // Overload for direct comparison in the oracle.
    bool operator==(const FuzzableStruct& other) const {
        return a == other.a && b == other.b;
    }
};

// Template function to run the core fuzzing logic for any given TYPE.
template <typename T>
void runFuzzer(FuzzedDataProvider& provider) {
    // 1. SETUP: Create a SortedVector and a mirror std::vector to act as an oracle.
    android::SortedVector<T> sortedVec;
    std::vector<T> mirrorVec;

    // 2. PARAMETER PARSING & POPULATION: Populate the vector with fuzzer-generated data.
    // The number of initial elements is determined by the fuzzer.
    size_t initialSize = provider.ConsumeIntegralInRange<size_t>(0, 1000);
    for (size_t i = 0; i < initialSize; ++i) {
        T val;
        // Check if T is our custom struct and populate it, otherwise use a generic method.
        if constexpr (std::is_same_v<T, FuzzableStruct>) {
            val = {provider.ConsumeIntegral<int>(), provider.ConsumeIntegral<char>()};
        } else {
            val = provider.ConsumeIntegral<T>();
        }

        // Add the value to both our target vector and the oracle.
        sortedVec.add(val);
        mirrorVec.push_back(val);
    }
    // The oracle must also be sorted to correctly predict behavior.
    std::sort(mirrorVec.begin(), mirrorVec.end());

    // 3. TARGET INVOCATION & VERIFICATION: In a loop, remove items and verify state.
    while (provider.remaining_bytes() > sizeof(T) && !sortedVec.isEmpty()) {
        T itemToRemove;

        // Use the fuzzer to choose a removal strategy, as outlined in the generation plan.
        int strategy = provider.ConsumeIntegralInRange<int>(0, 2);

        if (strategy == 0 && !mirrorVec.empty()) {
            // Strategy 1: Remove an element that is known to exist.
            size_t idxToRemove = provider.ConsumeIntegralInRange<size_t>(0, mirrorVec.size() - 1);
            itemToRemove = mirrorVec[idxToRemove];
        } else if (strategy == 1) {
            // Strategy 2: Attempt to remove a random, potentially non-existent element.
            if constexpr (std::is_same_v<T, FuzzableStruct>) {
                itemToRemove = {provider.ConsumeIntegral<int>(), provider.ConsumeIntegral<char>()};
            } else {
                itemToRemove = provider.ConsumeIntegral<T>();
            }
        } else {
            // Strategy 3: Remove an edge-case element (first, last, or middle).
            if (sortedVec.isEmpty()) continue;
            size_t idx = provider.ConsumeIntegralInRange<size_t>(0, sortedVec.size() - 1);
            itemToRemove = sortedVec[idx];
        }

        // Check if the item exists in our oracle *before* calling remove().
        auto it = std::find(mirrorVec.begin(), mirrorVec.end(), itemToRemove);
        bool shouldBeFound = (it != mirrorVec.end());

        // Invoke the target function.
        ssize_t removeResult = sortedVec.remove(itemToRemove);

        // 4. ERROR HANDLING & ORACLE VERIFICATION
        if (shouldBeFound) {
            // The item was in the vector, so remove() should have succeeded.
            if (removeResult < 0) __builtin_trap();
            // Update the oracle.
            mirrorVec.erase(it);
        } else {
            // The item was not in the vector, so remove() should have failed.
            if (removeResult >= 0) __builtin_trap();
        }

        // Verify that the size of the SortedVector matches the oracle.
        if (sortedVec.size() != mirrorVec.size()) __builtin_trap();

        // CRITICAL: Verify the core invariant that the vector remains sorted.
        for (size_t i = 0; i + 1 < sortedVec.size(); ++i) {
            if (sortedVec[i+1] < sortedVec[i]) {
                // This indicates a critical bug in the remove logic.
                __builtin_trap();
            }
        }
    }
    // 5. CLEANUP: All objects are stack-allocated and will be cleaned up automatically.
}

// Main fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider provider(data, size);

    // Randomly choose which data type to test in this run.
    // This allows a single fuzzer to cover multiple template instantiations.
    int type_choice = provider.ConsumeIntegralInRange<int>(0, 1);
    if (type_choice == 0) {
        runFuzzer<int>(provider);
    } else {
        runFuzzer<FuzzableStruct>(provider);
    }

    return 0;
}
