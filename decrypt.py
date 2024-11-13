from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

import base64
import pandas as pd


# ?: Helper function to apply padding
def pad(data):
    """
    The function `pad` uses PKCS7 padding with a block size of 128 to pad the input
    data.

    :param data: It looks like the code snippet you provided is a function called
    `pad` that pads the input data using PKCS7 padding with a block size of 128. The
    `data` parameter is the input data that you want to pad. You can pass any byte
    string or data that you want to
    :return: The function `pad(data)` returns the input data after applying PKCS7
    padding with a block size of 128.
    """
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data


# ?: Helper function to remove padding
def unpad(data):
    """
    The function `unpad` removes padding from data using PKCS7 padding scheme with a
    block size of 128.

    :param data: It seems like the code snippet you provided is attempting to unpad
    data using PKCS7 padding scheme with a block size of 128. However, you have not
    provided the actual `data` parameter that needs to be unpadded. Could you please
    provide the `data` parameter so that I can
    :return: The function `unpad(data)` returns the unpadded data after removing
    padding using PKCS7 padding scheme with a block size of 128.
    """
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data


def load_key():
    """
    The function `load_key` reads and returns the content of a binary file named
    "secret.key" located in the "./keys" directory.
    :return: The function `load_key()` is returning the content of the file
    "./keys/secret.key" as a binary string.
    """
    with open("./keys/secret.key", "rb") as key_file:
        return key_file.read()


def decrypt_column(input_csv, output_csv, columns):
    key = load_key()

    # ?: Load the encrypted CSV
    df = pd.read_csv(input_csv, sep=",", encoding="utf-8")
    print("Before:", "\n", df.head())

    # ?: Decrypt the target column
    decrypted_column = []
    for column in columns:
        for encrypted_value in df[column]:
            # ?: Decode the base64 string to get IV + encrypted value
            encrypted_data = base64.b64decode(encrypted_value)
            iv = encrypted_data[:16]  # ?: Extract IV (first 16 bytes)
            encrypted_value = encrypted_data[16:]  # ?: Extract encrypted data

            cipher = Cipher(
                algorithms.AES(key), modes.CBC(iv), backend=default_backend()
            )
            decryptor = cipher.decryptor()

            padded_data = decryptor.update(encrypted_value) + decryptor.finalize()
            decrypted_value = unpad(
                padded_data
            ).decode()  # ?: Remove padding and decode to string

            decrypted_column.append(decrypted_value)

        # ?: sReplace the column in the DataFrame with the decrypted data
        df[column] = decrypted_column

    # ?: Save the decrypted CSV
    df.to_csv(output_csv, index=False, encoding="utf-8")
    print("-" * 100)
    print("After:", "\n", df.head())
    print(f"Decrypted column '{columns}' and saved to {output_csv}")


if __name__ == "__main__":
    decrypt_column(
        "./output/results.csv",
        "./output/decrypted/results.csv",
        ["BP_NAME"],
    )
