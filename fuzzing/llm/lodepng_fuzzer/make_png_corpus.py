from PIL import Image, ImageDraw
import os

def create_gradient(width, height):
    """Create a horizontal gradient."""
    base = Image.new('RGB', (width, height), color=0)
    draw = ImageDraw.Draw(base)
    for i in range(width):
        color = 255 - int(255 * (i / width))
        draw.line((i, 0, i, height), fill=(color, color, color))
    return base

def generate_png_samples(directory, num_samples=10):
    if not os.path.exists(directory):
        os.makedirs(directory)

    for i in range(num_samples):
        # Generate different sizes
        width, height = 50 * (i + 1), 50 * (i + 1)

        # Plain image
        img = Image.new('RGB', (width, height), color=(i * 10, i * 20, i * 30))
        img.save(f'{directory}/sample_plain_{i}.png')

        # Gradient image
        img = create_gradient(width, height)
        img.save(f'{directory}/sample_gradient_{i}.png')

        # RGBA image
        img = Image.new('RGBA', (width, height), color=(i * 10, i * 20, i * 30, i * 40))
        img.save(f'{directory}/sample_rgba_{i}.png')

        # Grayscale image
        img = Image.new('L', (width, height), color=i * 10)
        img.save(f'{directory}/sample_gray_{i}.png')

# Usage
generate_png_samples('png_corpus')
