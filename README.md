# stegosafeCLI

![License](https://img.shields.io/badge/License-MIT-green)
![Python](https://img.shields.io/badge/Python-3.6%2B-blue)
![Encryption](https://img.shields.io/badge/Encryption-AES--256-critical)
![Steganography](https://img.shields.io/badge/Steganography-LSB-important)

> **Encrypt. Split. Vanish.**  
> Your secrets hidden inside everyday images — and only you can bring them back.


> 🧪 Try the web version now: [StegoSafe Web Demo →](https://stegosafe.com/demo/)  
> 🧰 Prefer the terminal? You're in the right place.

---

## ✨ Features

- **AES-256 Encryption**: Secrets are encrypted using military-grade AES-256 in CBC mode.
- **Quantum-Resistant Security**: AES-256 is considered resilient even against quantum computing attacks.
- **Shamir's Secret Sharing**: Your encryption key is split into 5 pieces — only 3 are needed to recover it.
- **Steganography**: Secrets are invisibly embedded inside ordinary PNG images, undetectable to the naked eye.
- **Threshold Recovery**: Lose 2 images? No problem. 3 shares are enough to recover your data.
- **100% Local**: All operations happen on your device. No cloud, no leaks.

---

## 📦 Requirements

- Python 3.6 or higher
- Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```

Dependencies:
- cryptography
- Pillow
- numpy

---

## ⚙️ Installation

1. Clone this repository or download the source code.
2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Usage

### Embedding a Secret

Encrypt and embed a secret into images:

```bash
python stegosafe_cli.py embed -i <input_folder> -s "<your_secret_text>" -o <output_folder>
```

Arguments:
- `-i`, `--input_folder`: Directory containing source images (must be PNG files).
- `-s`, `--secret`: The text you want to hide securely.
- `-o`, `--output_folder`: Directory where steganographic images will be saved.

**Example**:
```bash
python stegosafe_cli.py embed -i test_images -s "This is my hidden message" -o output_images
```

---

### Recovering a Secret

Recover the hidden secret from steganographic images:

```bash
python stegosafe_cli.py recover -i <stego_folder>
```

Arguments:
- `-i`, `--stego_folder`: Directory containing the steganographic images.

**Example**:
```bash
python stegosafe_cli.py recover -i output_images
```

---

## 🛡️ How It Works

1. **Encrypt** your secret with AES-256 and a randomly generated key.
2. **Split** the key into 5 shares using Shamir's Secret Sharing (threshold: 3 of 5).
3. **Embed** each share along with the full ciphertext into separate images using LSB steganography.
4. **Recover** the secret using any 3 valid stego images.

Even if attackers find some images, without the required threshold, **your secret remains mathematically protected**.

---

## 🔒 Security Notes

- **Use PNGs**: Only lossless PNG format is supported to preserve hidden data integrity.
- **Threshold Protection**: Fewer than 3 images reveal nothing about the secret.
- **Imperceptibility**: Only least significant bits are modified, making detection by visual inspection or naive analysis very difficult.
- **Complete Locality**: Your data never leaves your machine.

---

## 🚀 What's Next?

For updates and improvements, follow this repo — or contribute!

🔒 **Protect your future secrets today — and be ready for tomorrow.**

> Stay tuned for updates. Follow the project for early access.

---

## ⚠️ Disclaimer

This tool is intended for lawful, ethical, and personal use only.  
The author assumes **no responsibility** for misuse.

---

## 📜 License

Released under the **MIT License**.
