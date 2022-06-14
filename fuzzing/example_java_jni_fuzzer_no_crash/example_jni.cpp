// Copyright 2021 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <limits>
#include <string>
#include <nativehelper/JNIHelp.h>
#include <jni.h>
#include <stdio.h>
#include "example_jni.h"

// simple function containing a crash that requires coverage and string compare
// instrumentation for the fuzzer to find
__attribute__((optnone)) void parseInternal(const std::string &input) {
  constexpr int bar = std::numeric_limits<int>::max() - 5;
  if (input[0] == 'a' && input[1] == 'b' && input[5] == 'c') {
    if (input.find("should report no crash") != std::string::npos) {
      [[maybe_unused]] char foo = input[input.size()];
    }
  }
}

JNIEXPORT jboolean JNICALL Java_ExampleJavaJniFuzzer_parse(
    JNIEnv *env, jobject o, jstring bytes) {
  const char *input(env->GetStringUTFChars(bytes, nullptr));
  parseInternal(input);
  env->ReleaseStringUTFChars(bytes, input);
  return false;
}
