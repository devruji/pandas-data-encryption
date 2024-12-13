from dotenv import load_dotenv

import os

load_dotenv()  # ?: Load environment variables from the .env file


def generate_key() -> None:
    """
    Generates a 256-bit (32-byte) AES key and saves it to a file specified by
    the parameter `key_name` located in the "./keys" directory.

    :param key_name: The name of the key file to write to.
    :return: None
    """
    key = os.urandom(32)  # AES-256 requires a 256-bit key (32 bytes)
    with open(f"./keys/{os.getenv('KEY_NAME')}", "wb") as key_file:
        key_file.write(key)


if __name__ == "__main__":
    generate_key()
    print("OK")
