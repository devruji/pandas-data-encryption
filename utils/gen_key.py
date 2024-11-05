import os


# Step 1: Generate a 256-bit (32-byte) AES key (run only once to create and save the key)
def generate_key():
    key = os.urandom(32)  # AES-256 requires a 256-bit key (32 bytes)
    with open("./keys/secret.key", "wb") as key_file:
        key_file.write(key)


if __name__ == "__main__":
    generate_key()
    print("OK")
