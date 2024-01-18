import zlib
import os

def generate_compressed_samples(directory, num_samples=10):
    if not os.path.exists(directory):
        os.makedirs(directory)

    for i in range(num_samples):
        # Create a simple byte pattern
        pattern = bytes([i % 256]) * (i + 1)

        # Compress the pattern
        compressed_data = zlib.compress(pattern)

        # Save the compressed data to a file
        with open(f'{directory}/sample_{i}.zlib', 'wb') as f:
            f.write(compressed_data)

# Usage
generate_compressed_samples('zlib_corpus')
