import os


# ?: Step 1: Generate a 256-bit (32-byte) AES key (run only once to create and save the key)
def generate_key() -> None:
    """
    The function `generate_key` generates a 256-bit (32-byte) AES key and
    saves it to a file named "./keys/aes-256-secret.key". The `generate_key`
    function does not have any parameters and does not return any value.

    :return: None
    """

    key = os.urandom(32)  # ?: AES-256 requires a 256-bit key (32 bytes)
    with open("./keys/aes-256-secret.key", "wb") as key_file:
        key_file.write(key)


if __name__ == "__main__":
    generate_key()
    print("OK")
