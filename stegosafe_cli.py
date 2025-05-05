import os
import argparse
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import secrets
import random
from PIL import Image
import numpy as np

# ===== Crypto Utilities =====
def encrypt_secret(secret_text):
    key = secrets.token_bytes(32)  # 256-bit key
    iv = secrets.token_bytes(16)   # 128-bit IV
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    # Pad plaintext
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(secret_text.encode()) + padder.finalize()

    # Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return key, iv + ciphertext

def decrypt_secret(key, iv_ciphertext):
    # Ensure key is 32 bytes
    if len(key) != 32:
        print(f"Warning: Key length {len(key)} != 32, adjusting size")
        key = key[:32] if len(key) > 32 else key.ljust(32, b'\x00')
    
    # Extract IV and ciphertext
    iv = iv_ciphertext[:16]
    ciphertext = iv_ciphertext[16:]
    
    # Ensure ciphertext length is a multiple of 16
    if len(ciphertext) % 16 != 0:
        print(f"Warning: Ciphertext length {len(ciphertext)} is not a multiple of 16")
        padding_needed = 16 - (len(ciphertext) % 16)
        ciphertext = ciphertext + b'\x00' * padding_needed
        
    # Create decryptor
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    
    try:
        # Decrypt
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext.decode()
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        # Try to return without removing padding
        try:
            return padded_plaintext.decode('utf-8', errors='ignore')
        except:
            return f"[Unable to decrypt: {str(e)}]"

# ===== Shamir's Secret Sharing =====
def split_secret(secret_bytes, n, k):
    """
    Split the secret into n shares, requiring k shares to recover
    Implemented using Shamir's Secret Sharing
    """
    # Convert secret to integer
    secret_int = int.from_bytes(secret_bytes, 'big')
    prime = 2**256 - 189  # A prime close to 2^256
    
    # Generate random coefficients
    coeffs = [secret_int]
    for _ in range(k - 1):
        coeffs.append(random.randrange(1, prime))
    
    # Calculate value for each share
    shares = []
    for i in range(1, n + 1):
        x = i
        y = coeffs[0]
        for j in range(1, k):
            term = (coeffs[j] * pow(x, j, prime)) % prime
            y = (y + term) % prime
        
        # Convert to bytes
        y_bytes = y.to_bytes(32, byteorder='big')
        shares.append((x, y_bytes))
    
    return shares

def recover_secret(shares):
    """Recover secret from k shares"""
    # We use a fixed 256-bit prime
    prime = 2**256 - 189
    
    # Extract x and y
    xs = []
    ys = []
    for x, y_bytes in shares:
        xs.append(x)
        y = int.from_bytes(y_bytes, byteorder='big')
        ys.append(y)
    
    # Use Lagrange interpolation to recover the secret
    secret = 0
    for i in range(len(shares)):
        xi = xs[i]
        yi = ys[i]
        
        # Calculate Lagrange basis polynomial
        num = 1
        den = 1
        for j in range(len(shares)):
            if i == j:
                continue
            xj = xs[j]
            num = (num * (0 - xj)) % prime
            den = (den * (xi - xj)) % prime
        
        # Use Fermat's Little Theorem to calculate modular inverse
        den_inv = pow(den, prime - 2, prime)
        
        # Update secret value
        term = (yi * num * den_inv) % prime
        secret = (secret + term) % prime
    
    # Convert back to bytes, fixed 32 bytes length
    return secret.to_bytes(32, byteorder='big')

# ===== Steganography =====
def embed_data_in_image(image, data_bytes):
    """Embed data in the LSB bits of the image"""
    # Prepare data: structure is [length(4 bytes) + data]
    data_len = len(data_bytes)
    header = struct.pack(">I", data_len)
    full_data = header + data_bytes
    
    # Convert data to bit sequence
    bits = ''.join(format(b, '08b') for b in full_data)
    
    # Convert image
    img = image.convert('RGB')
    width, height = img.size
    pixels = img.load()
    
    # Check image capacity
    max_bits = width * height * 3  # RGB 3 bits per pixel
    if len(bits) > max_bits:
        raise ValueError(f"Data too long ({len(bits)} bits) to embed in image ({max_bits} bits)")
    
    # Embed data
    bit_index = 0
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            
            # Process R channel
            if bit_index < len(bits):
                r = (r & 0xFE) | int(bits[bit_index])
                bit_index += 1
            
            # Process G channel
            if bit_index < len(bits):
                g = (g & 0xFE) | int(bits[bit_index])
                bit_index += 1
            
            # Process B channel
            if bit_index < len(bits):
                b = (b & 0xFE) | int(bits[bit_index])
                bit_index += 1
            
            pixels[x, y] = (r, g, b)
            
            if bit_index >= len(bits):
                break
        if bit_index >= len(bits):
            break
    
    return img

def extract_data_from_image(image):
    """Extract data from image"""
    # Convert image
    img = image.convert('RGB')
    width, height = img.size
    pixels = img.load()
    
    # Extract all LSB bits
    bits = ""
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            bits += str(r & 1)
            bits += str(g & 1)
            bits += str(b & 1)
            
            # Once we have enough bits to extract length, check data length
            if len(bits) == 32:  # 4 bytes * 8 bits = 32 bits
                # Extract length
                length_bytes = bytes(int(bits[i:i+8], 2) for i in range(0, 32, 8))
                data_length = struct.unpack(">I", length_bytes)[0]
                
                # Check if data length is reasonable
                if data_length > 1000000:  # Set a reasonable upper limit
                    print(f"Warning: Unreasonable data length ({data_length})")
                    return b""
                
                # Calculate total bits to extract
                total_bits = 32 + (data_length * 8)  # Length bits + data bits
                
                # If we already have enough bits, truncate and return
                if len(bits) >= total_bits:
                    bits = bits[:total_bits]
                    break
    
    # Ensure bit count is a multiple of 8
    bits_len = (len(bits) // 8) * 8
    bits = bits[:bits_len]
    
    # Bits to bytes
    bytes_data = bytearray()
    for i in range(0, len(bits), 8):
        if i + 8 <= len(bits):
            byte = int(bits[i:i+8], 2)
            bytes_data.append(byte)
    
    # Extract length header
    if len(bytes_data) < 4:
        return b""
    
    data_length = struct.unpack(">I", bytes_data[:4])[0]
    
    # Return actual data
    if 4 + data_length <= len(bytes_data):
        return bytes(bytes_data[4:4+data_length])
    else:
        # Return all possible data
        return bytes(bytes_data[4:])

# ===== Main Functions =====
def encrypt_and_embed(input_folder, secret, output_folder):
    """
    Encrypt a secret and embed it into images
    """
    # Create output folder if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)
    
    # Encrypt the secret
    print(f"Encrypting text: '{secret}'")
    key, ciphertext = encrypt_secret(secret)
    print(f"Key length: {len(key)} bytes, Ciphertext length: {len(ciphertext)} bytes")
    
    # Split the key using Shamir's Secret Sharing
    n = 5  # Total number of shares
    k = 3  # Minimum shares required to recover
    shares = split_secret(key, n, k)
    print(f"Key split into {n} shares")
    
    # Get all image files from the input folder
    image_files = [f for f in os.listdir(input_folder) 
                   if os.path.isfile(os.path.join(input_folder, f)) and
                   f.lower().endswith(('.png', '.jpg', '.jpeg'))]
    
    # Check if we have enough images
    if len(image_files) < n:
        raise ValueError(f"Not enough images in folder. Need at least {n}, found {len(image_files)}")
    
    # Use the first n images
    selected_images = image_files[:n]
    
    # Embed each share into an image along with the ciphertext
    for i, (x, y_bytes) in enumerate(shares):
        # Prepare the data to embed:
        # [share index (1 byte) + share value (y_bytes) + ciphertext]
        data_to_embed = bytes([x]) + y_bytes + ciphertext
        print(f"Share {i+1}: x={x}, y length={len(y_bytes)}")
        print(f"Total data length to embed: {len(data_to_embed)} bytes")
        
        # Open the image
        img_path = os.path.join(input_folder, selected_images[i])
        img = Image.open(img_path)
        
        # Embed the data
        stego_img = embed_data_in_image(img, data_to_embed)
        
        # Save the image as PNG to avoid lossy compression
        output_path = os.path.join(output_folder, f"stego_{i+1}.png")
        stego_img.save(output_path, format='PNG')
        print(f"Saved: {output_path}")
    
    print(f"Encryption and embedding complete. Created {n} stego images")

def extract_and_recover(stego_folder):
    """
    Extract and recover the secret from stego images
    """
    # Get all stego images
    stego_files = [f for f in os.listdir(stego_folder)
                   if os.path.isfile(os.path.join(stego_folder, f)) and
                   f.lower().endswith('.png')]
    
    # Sort the stego files to maintain consistent order
    stego_files.sort()
    
    print(f"Found {len(stego_files)} stego images")
    
    if len(stego_files) < 3:
        raise ValueError("At least 3 stego images are required to recover the secret")
    
    # Extract data from each stego image
    shares = []
    ciphertext_length = None
    ciphertext = None
    
    # First, we need to determine the ciphertext length
    # Look at the first image
    first_image_path = os.path.join(stego_folder, stego_files[0])
    img = Image.open(first_image_path)
    data = extract_data_from_image(img)
    
    if len(data) < 34:  # 1 byte for x + 32 bytes for y + at least 1 byte for ciphertext
        raise ValueError(f"Invalid data extracted from {stego_files[0]}")
    
    # Data structure: [x (1 byte) + y (32 bytes) + ciphertext]
    ciphertext_length = len(data) - 33  # Remaining bytes after x and y
    print(f"Estimated ciphertext length: {ciphertext_length}")
    
    # Now process all images
    for stego_file in stego_files:
        stego_path = os.path.join(stego_folder, stego_file)
        print(f"\nProcessing: {stego_path}")
        
        # Open the image and extract data
        img = Image.open(stego_path)
        data = extract_data_from_image(img)
        print(f"Extracted data length: {len(data)} bytes")
        
        if len(data) < 33:  # Minimum 1 byte for x + 32 bytes for y
            print(f"Warning: Invalid data in {stego_file}, skipping")
            continue
        
        # Extract share index (x) and y-value
        x = data[0]
        y = data[1:33]
        print(f"x value: {x}")
        
        # If this is the first valid share, also extract the ciphertext
        if ciphertext is None and len(data) >= 33 + ciphertext_length:
            ciphertext = data[33:33+ciphertext_length]
            print(f"y length: {len(y)}, ciphertext length: {len(ciphertext)}")
        
        # Add share to our collection
        shares.append((x, y))
        print(f"Extracted share: x={x}, y length={len(y)}")
        
        # Once we have at least k=3 shares, we can stop
        if len(shares) >= 3 and ciphertext is not None:
            break
    
    # Ensure we have enough shares and the ciphertext
    if len(shares) < 3:
        raise ValueError(f"Not enough valid shares found. Need at least 3, found {len(shares)}")
    if ciphertext is None:
        raise ValueError("Failed to extract ciphertext")
    
    # Recover the key
    print(f"\nCollected {len(shares)} shares, starting recovery")
    key = recover_secret(shares)
    print(f"Recovered key length: {len(key)} bytes")
    
    # Decrypt the secret
    secret = decrypt_secret(key, ciphertext)
    
    print("\nRecovered secret:")
    print(secret)
    return secret

def main():
    parser = argparse.ArgumentParser(description='stegosafeCLI: Securely encrypt and embed secrets in images')
    subparsers = parser.add_subparsers(dest='command')
    
    # Embed command
    embed_parser = subparsers.add_parser('embed', help='Encrypt and embed secret in images')
    embed_parser.add_argument('-i', '--input_folder', required=True, help='Folder with original images')
    embed_parser.add_argument('-s', '--secret', required=True, help='Secret text to hide')
    embed_parser.add_argument('-o', '--output_folder', required=True, help='Folder to output stego images')
    
    # Recover command
    recover_parser = subparsers.add_parser('recover', help='Recover secret from stego images')
    recover_parser.add_argument('-i', '--stego_folder', required=True, help='Folder with stego images')
    
    args = parser.parse_args()
    
    if args.command == 'embed':
        encrypt_and_embed(args.input_folder, args.secret, args.output_folder)
    elif args.command == 'recover':
        extract_and_recover(args.stego_folder)
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 