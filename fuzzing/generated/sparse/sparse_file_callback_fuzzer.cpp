// Fuzz harness for sparse_file_callback
// Target: int sparse_file_callback(struct sparse_file *s, bool sparse, bool crc,
//                int (*write)(void *priv, const void *data, size_t len), void *priv)

#include <fuzzer/FuzzedDataProvider.h>
#include <sparse/sparse.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>
#include <algorithm>

// Constants for fuzzing constraints
constexpr size_t kMaxFileSize = 10 * 1024 * 1024;  // 10MB max to prevent OOM
constexpr size_t kMaxBlocks = 100;  // Limit number of blocks to add
constexpr size_t kMaxDataBlockSize = 64 * 1024;  // 64KB max per data block
constexpr size_t kMinBlockSize = 512;
constexpr size_t kMaxCallbackFailures = 10;  // Limit callback failure simulation

// Callback context structure to track and control callback behavior
struct CallbackContext {
    size_t total_written;
    size_t max_size;
    bool should_fail;
    size_t fail_after_bytes;
    size_t failure_count;  // Changed from int to size_t to match comparison
    bool validate_data;
    std::vector<uint8_t> data_buffer;  // For data validation
};

// Fuzz callback function that simulates various I/O behaviors
static int fuzz_callback(void* priv, const void* data, size_t len) {
    if (!priv) {
        return -1;  // Invalid context
    }

    auto* ctx = static_cast<CallbackContext*>(priv);

    // Simulate write failure at specific points
    if (ctx->should_fail && ctx->total_written >= ctx->fail_after_bytes) {
        ctx->failure_count++;
        if (ctx->failure_count <= kMaxCallbackFailures) {
            return -1;  // Simulate write failure
        }
    }

    // Check for overflow conditions
    if (ctx->total_written + len < ctx->total_written) {
        return -1;  // Integer overflow
    }

    // Enforce maximum size limit
    if (ctx->total_written + len > ctx->max_size) {
        return -1;  // Size limit exceeded
    }

    // Track written data
    ctx->total_written += len;

    // Optionally validate data patterns
    if (ctx->validate_data && data && len > 0) {
        // Store first few bytes for pattern validation
        size_t copy_len = std::min(len, size_t(16));
        if (ctx->data_buffer.size() < 1024) {  // Limit buffer size
            ctx->data_buffer.insert(ctx->data_buffer.end(), 
                                  static_cast<const uint8_t*>(data),
                                  static_cast<const uint8_t*>(data) + copy_len);
        }
    }

    return 0;  // Success
}

// Helper to create a temporary file with fuzzer data
static int create_temp_fd_with_data(const uint8_t* data, size_t size) {
    char temp_path[] = "/data/local/tmp/sparse_fuzz_XXXXXX";
    int fd = mkstemp(temp_path);
    if (fd < 0) {
        return -1;
    }

    // Write fuzzer data to temp file
    if (write(fd, data, size) != static_cast<ssize_t>(size)) {
        close(fd);
        unlink(temp_path);
        return -1;
    }

    // Reset to beginning for reading
    lseek(fd, 0, SEEK_SET);

    // Unlink immediately so file is deleted when fd is closed
    unlink(temp_path);

    return fd;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Parse configuration from fuzzer input
    bool use_import = fdp.ConsumeBool();
    bool use_auto_import = use_import && fdp.ConsumeBool();
    bool sparse_flag = fdp.ConsumeBool();
    bool crc_flag = fdp.ConsumeBool();

    // Choose block size from valid values
    uint32_t block_size = fdp.PickValueInArray({512, 1024, 2048, 4096});

    // Constrain file length to prevent OOM
    int64_t file_len = fdp.ConsumeIntegralInRange<int64_t>(0, kMaxFileSize);

    // Ensure file length is aligned to block size for valid sparse files
    file_len = (file_len / block_size) * block_size;
    if (file_len == 0) {
        file_len = block_size;  // Minimum valid size
    }

    // Create sparse file structure
    std::unique_ptr<sparse_file, decltype(&sparse_file_destroy)> s(nullptr, sparse_file_destroy);

    if (use_import) {
        // Option A: Import from fuzzer-generated data
        size_t import_data_size = fdp.ConsumeIntegralInRange<size_t>(0, std::min(size_t(file_len), fdp.remaining_bytes()));
        if (import_data_size > 0) {
            std::vector<uint8_t> import_data = fdp.ConsumeBytes<uint8_t>(import_data_size);

            int fd = create_temp_fd_with_data(import_data.data(), import_data.size());
            if (fd >= 0) {
                if (use_auto_import) {
                    // Use auto-detection of sparse format
                    bool verbose = fdp.ConsumeBool();
                    s.reset(sparse_file_import_auto(fd, false, verbose));
                } else {
                    // Direct import
                    s.reset(sparse_file_import(fd, false, false));
                }
                close(fd);
            }
        }
    } else {
        // Option B: Create new sparse file and add blocks
        sparse_file* raw_s = sparse_file_new(block_size, file_len);
        if (raw_s) {
            s.reset(raw_s);

            // Add various types of blocks based on fuzzer input
            size_t blocks_added = 0;
            int64_t current_offset = 0;

            while (fdp.remaining_bytes() > 0 && blocks_added < kMaxBlocks && current_offset < file_len) {
                uint8_t block_type = fdp.ConsumeIntegralInRange<uint8_t>(0, 3);

                // Calculate remaining space
                int64_t remaining = file_len - current_offset;
                if (remaining <= 0) break;

                // Determine block length (constrained by remaining space and block alignment)
                size_t block_len = fdp.ConsumeIntegralInRange<size_t>(
                    block_size, 
                    std::min(static_cast<size_t>(remaining), kMaxDataBlockSize)
                );
                block_len = (block_len / block_size) * block_size;  // Align to block size

                if (block_len == 0 || block_len > static_cast<size_t>(remaining)) {
                    block_len = std::min(static_cast<size_t>(block_size), static_cast<size_t>(remaining));
                }

                // Calculate block number
                unsigned int block_num = current_offset / block_size;

                switch (block_type) {
                    case 0: {  // DATA block
                        size_t data_size = std::min(block_len, fdp.remaining_bytes());
                        if (data_size > 0) {
                            std::vector<uint8_t> block_data = fdp.ConsumeBytes<uint8_t>(data_size);
                            // Pad to block_len if necessary
                            if (block_data.size() < block_len) {
                                block_data.resize(block_len, 0);
                            }
                            sparse_file_add_data(s.get(), block_data.data(), block_len, block_num);
                        }
                        break;
                    }
                    case 1: {  // FILL block
                        uint32_t fill_val = fdp.ConsumeIntegral<uint32_t>();
                        sparse_file_add_fill(s.get(), fill_val, block_len, block_num);
                        break;
                    }
                    case 2: {  // FD block
                        // Create a temporary fd with some data
                        size_t fd_data_size = std::min(block_len, fdp.remaining_bytes());
                        if (fd_data_size > 0) {
                            std::vector<uint8_t> fd_data = fdp.ConsumeBytes<uint8_t>(fd_data_size);
                            int temp_fd = create_temp_fd_with_data(fd_data.data(), fd_data.size());
                            if (temp_fd >= 0) {
                                int64_t fd_offset = fdp.ConsumeIntegralInRange<int64_t>(0, fd_data_size);
                                sparse_file_add_fd(s.get(), temp_fd, fd_offset, 
                                                  std::min(block_len, fd_data_size - fd_offset), block_num);
                                close(temp_fd);
                            }
                        }
                        break;
                    }
                    case 3: {  // Skip block (no data)
                        // Just advance offset without adding data
                        break;
                    }
                }

                current_offset += block_len;
                blocks_added++;
            }
        }
    }

    // If we don't have a valid sparse file at this point, bail out
    if (!s) {
        return 0;
    }

    // Setup callback context with fuzzer-controlled behavior
    CallbackContext ctx = {};
    ctx.total_written = 0;
    ctx.max_size = file_len * 2;  // Allow some overhead for sparse format
    ctx.should_fail = fdp.ConsumeBool();
    ctx.fail_after_bytes = fdp.ConsumeIntegralInRange<size_t>(0, file_len);
    ctx.failure_count = 0;
    ctx.validate_data = fdp.ConsumeBool();

    // Call the target function with our callback
    int ret = sparse_file_callback(s.get(), sparse_flag, crc_flag, fuzz_callback, &ctx);

    // The return value should be 0 on success or negative on error
    // We don't need to validate it specifically, but we can use it
    // to ensure the function completes without crashing
    (void)ret;

    // Cleanup is handled automatically by unique_ptr destructor

    return 0;
}
