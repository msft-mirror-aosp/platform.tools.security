/*
 * Copyright 2025 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <fuzzer/FuzzedDataProvider.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>

/*
 * This fuzzer demonstrates different crashes and failures
 * to test the crash detection capabilities of MTE.
 */

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  if (size < 1) {
    return 0;
  }

  uint8_t minLen = 1;
  uint8_t maxLen = size > 255 ? 255 : size;
  uint8_t allocSize = fdp.ConsumeIntegralInRange<uint8_t>(minLen, maxLen);
  uint8_t iterations = fdp.ConsumeIntegralInRange<uint8_t>(minLen, maxLen);
  uint8_t* heapBuf = (uint8_t*)malloc(allocSize);
  int stackBuf[allocSize];

  memcpy(heapBuf, data, allocSize);

  while (iterations--) {
    uint8_t choice = fdp.ConsumeIntegralInRange<uint8_t>(0, 10);
    switch (choice) {
      // Stack Out-of-Bounds Write
      case 0: {
        stackBuf[allocSize] = iterations;
        break;
      }

      // Heap Out-of-Bounds Write
      case 1: {
        heapBuf[allocSize] = iterations;
        break;
      }

      // Stack Out-of-Bounds Read
      case 2: {
        return stackBuf[size];
        break;
      }

      // Heap Out-of-Bounds Read
      case 3: {
        return data[size];
        break;
      }

      // Use-After-Free
      case 4: {
        uint8_t* buffer = (uint8_t*)malloc(allocSize);
        if (buffer) {
          buffer[0] = iterations;
          free(buffer);
          return buffer[0];
        }
        break;
      }

      // Abort.
      case 5: {
        abort();
        break;
      }

      // SIGILL.
      case 6: {
        __builtin_trap();
        break;
      }

      // Null Pointer Dereference
      case 7: {
        int* ptr = nullptr;
        *ptr = iterations;
        break;
      }

      // Following are done to ensure compiler doesn't optimize these out
      default: {
        heapBuf[0] = iterations;
        break;
      }
    }
  }
  int sum = 0;
  for (size_t i = 0; i < allocSize; i++) {
    sum += heapBuf[i];
  }
  free(heapBuf);
  return sum;
}
