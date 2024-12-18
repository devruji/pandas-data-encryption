import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> None:
    """
    Generate a 256-bit AES encryption key and save it to a file.

    The function uses the AES-GCM algorithm to generate a random 256-bit key.
    It saves the generated key to a binary file located in the "./keys" directory.
    The name of the file is specified by the environment variable 'KEY_NAME'.

    :return: None
    """

    key = AESGCM.generate_key(bit_length=256)

    with open(f"./keys/{os.getenv('KEY_NAME')}", "wb") as key_file:
        key_file.write(key)


if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv(".env.secret")

    generate_key()
    print("OK")
