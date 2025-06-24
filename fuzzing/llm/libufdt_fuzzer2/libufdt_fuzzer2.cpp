#include <cstdint>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>

#include <libfdt.h>

constexpr int FDT_BUFFER_SIZE = 8192;
constexpr int MAX_FUZZ_OPERATIONS = 100;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }
    FuzzedDataProvider stream(data, size);

    // === PHASE 1: Build a structurally valid FDT using the fuzzer data ===

    std::vector<char> fdt_buffer(FDT_BUFFER_SIZE);
    void *fdtp = fdt_buffer.data();

    int ret = fdt_create(fdtp, FDT_BUFFER_SIZE);
    if (ret != 0) return 0;

    fdt_add_mem_rsv(fdtp, 0, 0);

    // Keep track of the current node offset to add properties correctly
    int current_node_offset = fdt_add_subnode(fdtp, 0, ""); // Add root node

    int operations = 0;
    while (stream.remaining_bytes() > 1 && operations++ < MAX_FUZZ_OPERATIONS) {
        // Let the fuzzer decide what to do next.
        bool add_subnode = stream.ConsumeBool();
        if (add_subnode) {
            std::string name = stream.ConsumeRandomLengthString(31);
            current_node_offset = fdt_add_subnode(fdtp, current_node_offset, name.c_str());
            if (current_node_offset < 0) break; // Error, probably out of space
        } else {
            std::string prop_name = stream.ConsumeRandomLengthString(31);
            std::vector<uint8_t> prop_value = stream.ConsumeBytes<uint8_t>(stream.ConsumeIntegralInRange<size_t>(0, 256));
            fdt_setprop(fdtp, current_node_offset, prop_name.c_str(), prop_value.data(), prop_value.size());
        }
    }

    fdt_finish(fdtp);

    // === PHASE 2: Test the reading/parsing APIs on our valid FDT ===

    fdt_check_header(fdtp);

    int offset = -1;
    int depth = -1;
    while ((offset = fdt_next_node(fdtp, offset, &depth)) >= 0) {
        int prop_offset;
        for (prop_offset = fdt_first_property_offset(fdtp, offset);
             prop_offset >= 0;
             prop_offset = fdt_next_property_offset(fdtp, prop_offset))
        {
            const char *prop_name = nullptr;
            int prop_len = 0;
            const void *prop_value = fdt_getprop_by_offset(fdtp, prop_offset, &prop_name, &prop_len);
            if (prop_value) {
                uint8_t char_to_find = stream.ConsumeIntegral<uint8_t>();
                memchr(prop_value, char_to_find, prop_len);
            }
        }
    }

    std::string path_to_find = stream.ConsumeRandomLengthString(100);
    fdt_path_offset(fdtp, path_to_find.c_str());

    return 0;
}