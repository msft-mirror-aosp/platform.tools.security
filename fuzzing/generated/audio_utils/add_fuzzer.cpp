#include <audio_utils/CommandThread.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <cstdint>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    android::audio_utils::CommandThread commandThread;

    // Execute a series of random operations on the CommandThread instance
    // to test its state machine and thread lifecycle.
    while (fdp.remaining_bytes() > 0) {
        auto action = fdp.PickValueInArray<int>({0, 1, 2, 3});
        switch (action) {
            case 0: { // Add a command
                std::string name = fdp.ConsumeRandomLengthString(50);
                // The command itself is a no-op. The fuzzer's goal is to test the
                // CommandThread's queuing, execution, and threading logic, not the
                // content of the commands.
                commandThread.add(name, []() {});
                break;
            }
            case 1: { // Get the number of commands
                (void)commandThread.size();
                break;
            }
            case 2: { // Dump the command queue
                (void)commandThread.dump();
                break;
            }
            case 3: { // Quit the thread explicitly
                commandThread.quit();
                break;
            }
        }
    }

    // The CommandThread's destructor is implicitly called at the end of this
    // function. This is a critical part of the test, as it triggers quit()
    // and joins the internal thread, which can reveal race conditions or deadlocks,
    // especially if commands are still pending in the queue.
    return 0;
}
