"""
Generates clean PNG icons for the GovShield Chrome Extension.
Creates a professional Cyber Shield emblem with Indian flag tricolor accents.
Uses Pillow if available, otherwise generates pure raw PNG chunks.
"""

import os
import struct
import zlib

def create_shield_icon_bytes(size: int) -> bytes:
    """Generate a raw PNG for GovShield emblem at given size."""
    try:
        from PIL import Image, ImageDraw
        # Create high-res image and downscale for antialiasing
        scale = 4
        img = Image.new("RGBA", (size * scale, size * scale), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        w, h = size * scale, size * scale
        
        # Shield background (Navy Blue #0A192F)
        pad = int(w * 0.08)
        shield_pts = [
            (pad, pad),
            (w - pad, pad),
            (w - pad, int(h * 0.55)),
            (int(w * 0.5), h - pad),
            (pad, int(h * 0.55)),
        ]
        draw.polygon(shield_pts, fill=(10, 25, 47, 255), outline=(0, 212, 255, 255), width=max(2, int(scale * 1.5)))
        
        # Inner Shield Tricolor Accents (Saffron #FF9933, White #FFFFFF, Green #138808)
        inner_w = int(w * 0.45)
        cx = int(w * 0.5)
        
        # Saffron top band
        draw.rectangle([cx - inner_w//2, int(h * 0.25), cx + inner_w//2, int(h * 0.35)], fill=(255, 153, 51, 255))
        # White middle band
        draw.rectangle([cx - inner_w//2, int(h * 0.35), cx + inner_w//2, int(h * 0.45)], fill=(255, 255, 255, 255))
        # Green bottom band
        draw.rectangle([cx - inner_w//2, int(h * 0.45), cx + inner_w//2, int(h * 0.55)], fill=(19, 136, 8, 255))
        
        # Blue central node
        draw.ellipse([cx - int(w*0.06), int(h*0.37), cx + int(w*0.06), int(h*0.43)], fill=(0, 0, 128, 255))
        
        # Downscale smoothly
        img_final = img.resize((size, size), Image.Resampling.LANCZOS)
        import io
        buf = io.BytesIO()
        img_final.save(buf, format="PNG")
        return buf.getvalue()
    except ImportError:
        # Fallback minimal PNG builder
        return generate_raw_png(size)

def generate_raw_png(size: int) -> bytes:
    """Create a basic valid RGBA PNG using standard zlib."""
    width, height = size, size
    raw_data = bytearray()
    for y in range(height):
        raw_data.append(0) # filter byte 0 (None)
        for x in range(width):
            # Draw navy shield block
            if 2 <= x < width - 2 and 2 <= y < height - 2:
                if y < height * 0.35:
                    # Saffron / Cyan border
                    raw_data.extend((10, 25, 47, 255))
                elif y < height * 0.65:
                    raw_data.extend((0, 180, 216, 255)) # Shield core
                else:
                    raw_data.extend((19, 136, 8, 255))
            else:
                raw_data.extend((0, 0, 0, 0)) # transparent

    def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
        length = struct.pack('>I', len(data))
        crc = struct.pack('>I', zlib.crc32(chunk_type + data) & 0xffffffff)
        return length + chunk_type + data + crc

    png_header = b'\x89PNG\r\n\x1a\n'
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    ihdr = make_chunk(b'IHDR', ihdr_data)
    idat = make_chunk(b'IDAT', zlib.compress(bytes(raw_data)))
    iend = make_chunk(b'IEND', b'')
    return png_header + ihdr + idat + iend

def main():
    icons_dir = os.path.join(os.path.dirname(__file__), "icons")
    os.makedirs(icons_dir, exist_ok=True)
    
    sizes = [16, 32, 48, 128]
    for sz in sizes:
        png_data = create_shield_icon_bytes(sz)
        file_path = os.path.join(icons_dir, f"icon-{sz}.png")
        with open(file_path, "wb") as f:
            f.write(png_data)
        print(f"Generated {file_path} ({sz}x{sz})")

if __name__ == "__main__":
    main()
