#include <audio_utils/Trace.h>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

// Defines the set of actions the fuzzer can perform on the Object.
// This allows for more complex, stateful interactions than a simple loop.
enum class Action {
  SetString,
  SetArithmetic,
  ToTrace,
  Clear,
  kMaxValue = Clear,
};

// Generates strings that are more likely to trigger edge cases in the parsing
// and string replacement logic.
std::string GenerateInterestingString(FuzzedDataProvider &fdp) {
  // Characters that have a special meaning in the Object's format.
  constexpr char kSpecialChars[] = {'|', '"', '{', '}', '=', ' '};

  // Pick a generation strategy to create a variety of challenging inputs.
  switch (fdp.ConsumeIntegralInRange<int>(0, 4)) {
  case 0:
    // A completely random string.
    return fdp.ConsumeRandomLengthString(256);
  case 1:
    // A string composed entirely of special characters.
    {
      std::string s;
      size_t len = fdp.ConsumeIntegralInRange<size_t>(0, 128);
      s.reserve(len);
      for (size_t i = 0; i < len; ++i) {
        s += fdp.PickValueInArray(kSpecialChars);
      }
      return s;
    }
  case 2:
    // A string with a few special characters sprinkled in.
    {
      std::string s = fdp.ConsumeRandomLengthString(256);
      if (!s.empty()) {
        // Sprinkle in up to 5 special characters.
        for (size_t i = 0;
             i < fdp.ConsumeIntegralInRange<size_t>(1, 5); ++i) {
          s[fdp.ConsumeIntegralInRange<size_t>(0, s.size() - 1)] =
              fdp.PickValueInArray(kSpecialChars);
        }
      }
      return s;
    }
  case 3:
    // A string composed entirely of the character that gets replaced ('|'),
    // which specifically stresses the `appendWithReplacement` logic.
    return std::string(fdp.ConsumeIntegralInRange<size_t>(0, 256), '|');
  case 4:
    // An empty string, a common source of errors.
    return "";
  }
  return ""; // Should not be reached.
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  android::audio_utils::trace::Object trace_object;

  // Loop through a series of actions to simulate a complex object lifecycle.
  while (fdp.remaining_bytes() > 0) {
    const Action action = static_cast<Action>(fdp.ConsumeIntegralInRange<int>(
        0, static_cast<int>(Action::kMaxValue)));
    const std::string key = GenerateInterestingString(fdp);

    switch (action) {
    case Action::SetString: {
      const std::string value = GenerateInterestingString(fdp);
      trace_object.set(key, value);
      break;
    }
    case Action::SetArithmetic: {
      // Test various arithmetic types. FuzzedDataProvider handles edge cases
      // like min/max, NaN, and infinity automatically.
      switch (fdp.ConsumeIntegralInRange<int>(0, 7)) {
      case 0:
        trace_object.set(key, fdp.ConsumeIntegral<int32_t>());
        break;
      case 1:
        trace_object.set(key, fdp.ConsumeIntegral<int64_t>());
        break;
      case 2:
        trace_object.set(key, fdp.ConsumeFloatingPoint<float>());
        break;
      case 3:
        trace_object.set(key, fdp.ConsumeFloatingPoint<double>());
        break;
      case 4:
        trace_object.set(key, fdp.ConsumeIntegral<uint32_t>());
        break;
      case 5:
        trace_object.set(key, fdp.ConsumeIntegral<uint64_t>());
        break;
      case 6:
        trace_object.set(key, fdp.ConsumeBool());
        break;
      case 7:
        trace_object.set(key, fdp.ConsumeIntegral<char>());
        break;
      }
      break;
    }
    case Action::ToTrace: {
      // Exercise the final string construction with an interesting tag.
      const std::string tag = GenerateInterestingString(fdp);
      (void)trace_object.toTrace(tag);
      break;
    }
    case Action::Clear: {
      // Test object reuse and state clearing.
      trace_object.clear();
      // Also explicitly check the empty() state after clearing.
      (void)trace_object.empty();
      break;
    }
    }
  }

  // Final call to toTrace to ensure the object's final state is always
  // serialized, which is crucial for catching bugs in the destructor or
  // finalization logic.
  (void)trace_object.toTrace(fdp.ConsumeRandomLengthString(64));

  return 0;
}