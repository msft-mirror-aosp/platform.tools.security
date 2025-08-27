#include <audio_utils/SimpleLog.h>
#include <cstddef>
#include <cstdint>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include <fcntl.h> // For open()
#include <unistd.h> // For close()
#include <cmath> // For NAN, INFINITY

// Expanded collection of format specifiers and modifiers.
const char* const kIntFlags[] = {"", "-", "+", " ", "0", "#"};
const char* const kIntLength[] = {"", "hh", "h", "l", "ll", "z", "t", "j"};
const char* const kIntSpecifiers[] = {"d", "i", "u", "o", "x", "X"};

const char* const kDoubleFlags[] = {"", "-", "+", " ", "0", "#"};
const char* const kDoubleSpecifiers[] = {"f", "F", "e", "E", "g", "G", "a", "A"};

const char* const kStringFormats[] = {"%s", "%.*s"};
const char* const kCharFormats[] = {"%c"};
const char* const kPointerFormats[] = {"%p"};
const char* const kPercentFormat[] = {"%%"};
const char* const kWritebackFormat[] = {"%n"};


// This function generates a more complex and varied format string.
void FuzzLogVariadic(android::SimpleLog& slog, FuzzedDataProvider& provider) {
    // Generate a diverse set of arguments beforehand.
    // Use a wider range of integer types to test length modifiers.
    auto arg1_c = provider.ConsumeIntegral<signed char>();
    auto arg2_s = provider.ConsumeIntegral<short>();
    auto arg3_i = provider.ConsumeIntegral<int>();
    auto arg4_l = provider.ConsumeIntegral<long>();
    auto arg5_ll = provider.ConsumeIntegral<long long>();
    auto arg6_d = provider.ConsumeBool() ? provider.ConsumeFloatingPoint<double>()
                                        : provider.PickValueInArray({NAN, INFINITY, -INFINITY});
    std::string arg7_str = provider.ConsumeRandomLengthString(256);
    char arg8_c = provider.ConsumeIntegral<char>();
    void* arg9_p = &arg3_i; // Use a valid pointer to a stack variable.
    int arg10_n_val = 0; // For %n
    int* arg10_p = &arg10_n_val;
    int arg11_precision = provider.ConsumeIntegralInRange<int>(0, arg7_str.length());
    int arg12_width = provider.ConsumeIntegralInRange<int>(0, 128);

    std::string format_str;
    const int max_args = 8; // Number of distinct data arguments we can format.
    int args_to_use = provider.ConsumeIntegralInRange(0, max_args);

    // Call the appropriate log function based on the number of arguments.
    // The format string is constructed to match the arguments passed.
    switch (args_to_use) {
    case 0:
        slog.log(provider.ConsumeRandomLengthString(64).c_str());
        break;
    case 1: {
        // Test integer formatting
        format_str += "%";
        format_str += provider.PickValueInArray(kIntFlags);
        format_str += provider.PickValueInArray(kIntLength);
        format_str += provider.PickValueInArray(kIntSpecifiers);
        slog.log(format_str.c_str(), arg5_ll);
        break;
    }
    case 2: {
        // Test floating point formatting
        format_str += "%";
        format_str += provider.PickValueInArray(kDoubleFlags);
        if (provider.ConsumeBool()) {
            format_str += std::to_string(arg12_width);
        }
        if (provider.ConsumeBool()) {
            format_str += ".";
            format_str += std::to_string(arg11_precision);
        }
        format_str += provider.PickValueInArray(kDoubleSpecifiers);
        format_str += " ";
        format_str += provider.PickValueInArray(kCharFormats);
        slog.log(format_str.c_str(), arg6_d, arg8_c);
        break;
    }
    case 3: {
        // Test string and pointer
        format_str += provider.PickValueInArray(kStringFormats);
        format_str += " ";
        format_str += provider.PickValueInArray(kPointerFormats);
        format_str += " ";
        format_str += provider.PickValueInArray(kPercentFormat);
        slog.log(format_str.c_str(), arg11_precision, arg7_str.c_str(), arg9_p);
        break;
    }
    case 4: {
        // Test writeback and various integer sizes
        format_str += "%hhd %hd %d %ld ";
        format_str += provider.PickValueInArray(kWritebackFormat);
        slog.log(format_str.c_str(), arg1_c, arg2_s, arg3_i, arg4_l, arg10_p);
        break;
    }
    default: { // Cases 5, 6, 7, 8
        // Build a more complex, mixed format string
        std::string part1 = "%";
        part1 += provider.PickValueInArray(kIntFlags);
        part1 += "*";
        part1 += provider.PickValueInArray(kIntLength);
        part1 += provider.PickValueInArray(kIntSpecifiers);

        std::string part2 = "%";
        part2 += provider.PickValueInArray(kDoubleFlags);
        part2 += ".*";
        part2 += provider.PickValueInArray(kDoubleSpecifiers);

        std::string part3 = "%.*s";
        std::string part4 = "%c";
        std::string part5 = "%p";
        std::string part6 = "%n";

        format_str = provider.ConsumeRandomLengthString(16) + " " +
                     part1 + " " +
                     provider.ConsumeRandomLengthString(16) + " " +
                     part2 + " " +
                     part3 + " " +
                     part4 + " " +
                     part5 + " " +
                     part6 + " " +
                     provider.ConsumeRandomLengthString(16);

        // With a small probability, inject an invalid specifier to test error handling.
        if (provider.ConsumeProbability<double>() < 0.1) {
            format_str += "%z";
        }

        bool use_timestamp = provider.ConsumeBool();
        int64_t nowNs = use_timestamp ? provider.ConsumeIntegral<int64_t>() : -1;

        if (use_timestamp) {
            slog.log(nowNs, format_str.c_str(), arg12_width, arg5_ll, arg11_precision, arg6_d,
                     arg11_precision, arg7_str.c_str(), arg8_c, arg9_p, arg10_p);
        } else {
            slog.log(format_str.c_str(), arg12_width, arg5_ll, arg11_precision, arg6_d,
                     arg11_precision, arg7_str.c_str(), arg8_c, arg9_p, arg10_p);
        }
        break;
    }
    }
}


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider provider(data, size);

    // Fuzz the constructor parameter to test different log capacities.
    // Increased range to stress memory management more.
    size_t maxLogLines = provider.ConsumeIntegralInRange<size_t>(0, 1000);
    android::SimpleLog slog(maxLogLines);

    // Open /dev/null once to avoid repeated syscalls in the loop.
    int devNullFd = open("/dev/null", O_WRONLY);
    if (devNullFd < 0) {
        return 0; // Cannot proceed
    }

    // Perform a sequence of actions to test the stateful behavior of the class.
    while (provider.remaining_bytes() > 20) {
        // Pick an API to fuzz.
        auto api_call = provider.ConsumeIntegralInRange<uint8_t>(0, 3);
        switch (api_call) {
        case 0: {
            // Fuzz the variadic log functions.
            FuzzLogVariadic(slog, provider);
            break;
        }
        case 1: {
            // Fuzz the non-formatting logs() function.
            int64_t nowNs = provider.ConsumeIntegral<int64_t>();
            // Test with strings that might contain nulls or be very long.
            std::string str = provider.ConsumeRandomLengthString(1200);
            slog.logs(nowNs, str);
            break;
        }
        case 2: {
            // Fuzz the dumpToString() function.
            std::string prefix = provider.ConsumeRandomLengthString(16);
            size_t lines = provider.ConsumeIntegralInRange<size_t>(0, maxLogLines + 50);
            int64_t limitNs = provider.ConsumeIntegral<int64_t>();
            slog.dumpToString(prefix.c_str(), lines, limitNs);
            break;
        }
        case 3: {
            // Fuzz the dump(fd) function.
            std::string prefix = provider.ConsumeRandomLengthString(16);
            size_t lines = provider.ConsumeIntegralInRange<size_t>(0, maxLogLines + 50);
            // Fuzz limitNs with more extreme values.
            const int64_t kLimitNsValues[] = {0LL, -1LL, INT64_MIN, INT64_MAX};
            int64_t limitNs = provider.ConsumeBool()
                                      ? provider.ConsumeIntegral<int64_t>()
                                      : provider.PickValueInArray(kLimitNsValues);
            slog.dump(devNullFd, prefix.c_str(), lines, limitNs);
            break;
        }
        }
    }

    close(devNullFd);
    return 0;
}