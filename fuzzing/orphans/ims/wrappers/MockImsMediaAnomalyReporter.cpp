/*
 * Copyright (C) 2026 The Android Open Source Project
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

#include "ImsMediaAnomalyReporter.h"
#include "ImsMediaTrace.h"

void ImsMediaAnomalyReporter::reportAnomaly(const char* /*reason*/) {
  // Mock implementation for fuzzer
  // We can log the anomaly if needed, but for fuzzing we usually just want to
  // avoid linker errors. If the fuzzer hits this path, it might be interesting,
  // but we can't report it to Android framework.
}
