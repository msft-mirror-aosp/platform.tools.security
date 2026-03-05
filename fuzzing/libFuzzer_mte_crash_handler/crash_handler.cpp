/*
 * Copyright 2026 The Android Open Source Project
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

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void (*libfuzzer_death_callback)(void) = nullptr;

static volatile sig_atomic_t handling_signal = 0;

static struct sigaction original_handlers[NSIG];

/**
 * Intercept libFuzzer's death callback registration. LibFuzzer checks for this symbol during
 * initialization. By defining it, we capture the pointer to libFuzzer's crash handling function.
 * This allows us to invoke it manually from our own signal handler.
 */
extern "C" void __sanitizer_set_death_callback(void (*callback)(void)) {
    libfuzzer_death_callback = callback;
}

/**
 * This function first triggers libFuzzer to generate the crash artifacts, and then hands off
 * control to the system's original crash reporter (debuggerd).
 */
void CrashSignalHandler(int sig, siginfo_t *info, void *ucontext) {
    if (handling_signal) {
        _exit(1);
    }
    handling_signal = 1;

    // Invoke the captured libFuzzer death callback.
    // This forces libFuzzer to write the reproducer test case to the disk.
    if (libfuzzer_death_callback) {
        libfuzzer_death_callback();
    }

    /**
     * Chain to the original debuggerd handler. This ensures that the complete crash details are
     * passed to logcat for accurate classification.
     */
    if (sig < NSIG) {
        struct sigaction* original = &original_handlers[sig];

        if (original->sa_flags & SA_SIGINFO) {
            if (original->sa_sigaction) {
                original->sa_sigaction(sig, info, ucontext);
            }
        } else {
            if (original->sa_handler != SIG_IGN && original->sa_handler != SIG_DFL) {
                original->sa_handler(sig);
            } else {
                // If there was no upstream handler, reset and re-raise to die properly.
                struct sigaction sa = {};
                sa.sa_handler = SIG_DFL;
                sigaction(sig, &sa, nullptr);
                raise(sig);
            }
        }
    }
    _exit(1);
}

/**
 * This function runs automatically when the library loads, before main(). It sets up the
 * interception chain by installing the crash handler and saving the existing system handlers.
 */
__attribute__((constructor)) void RegisterCrashHandlers() {
    struct sigaction crash_sa;
    memset(&crash_sa, 0, sizeof(crash_sa));
    crash_sa.sa_sigaction = CrashSignalHandler;
    crash_sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&crash_sa.sa_mask);

    // List of signals libFuzzer typically handles
    int signals[] = {SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE, SIGTRAP};

    for (int sig : signals) {
        // Save the existing handler (debuggerd)
        if (sig < NSIG) {
            sigaction(sig, &crash_sa, &original_handlers[sig]);
        }
    }
}
