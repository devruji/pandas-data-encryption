from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

import os
import sys
import base64
import numpy as np
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


def encrypt_column(input_csv, output_csv, columns) -> None:
    """
    The `encrypt_column` function reads a CSV file, encrypts a specified column
    using AES encryption, and saves the encrypted data back to a new CSV file.

    :param input_csv: The `input_csv` parameter is the file path to the CSV file
    that contains the data you want to encrypt
    :param output_csv: The `output_csv` parameter in the `encrypt_column` function
    is the file path where the encrypted CSV data will be saved after encrypting the
    specified column. This parameter should be a string representing the file path
    where you want to save the encrypted CSV file. For example, it could be
    something like
    :param column_name: The `column_name` parameter in the `encrypt_column` function
    refers to the name of the column in the input CSV file that you want to encrypt.
    This function reads the input CSV file, encrypts the values in the specified
    column using AES encryption with a randomly generated IV (Initialization
    Vector), and
    """
    key = load_key()

    # ?: Load the CSV file
    df = pd.read_csv(input_csv, sep=r"\|\,", engine="python")
    df.columns = df.columns.str.strip("|")
    df = df.map(lambda x: x.strip("|") if isinstance(x, str) else x).replace("", np.nan)
    print("Before", "\n", df.head())

    # ?: Encrypt the target column
    for column_name in columns:
        encrypted_column = []
        if column_name not in df.columns:
            raise Exception(f"Column: {column_name} not found in dataset")

        for value in df[column_name]:
            if value is np.nan:
                encrypted_column.append(np.nan)
                continue
            iv = os.urandom(16)  # !: AES block size is 16 bytes, so IV is 16 bytes
            cipher = Cipher(
                algorithms.AES(key), modes.CBC(iv), backend=default_backend()
            )
            encryptor = cipher.encryptor()

            padded_data = pad(str(value).encode())
            encrypted_value = encryptor.update(padded_data) + encryptor.finalize()

            # ?: Encode IV + encrypted value as a base64 string to store in CSV
            encrypted_column.append(base64.b64encode(iv + encrypted_value).decode())

        # ?: Replace the column in the DataFrame with the encrypted data
        df[column_name] = encrypted_column

    # ?: Save the encrypted CSV
    df.to_csv(output_csv, sep=",", encoding="utf-8", index=False)
    print("-" * 100)
    print("After", "\n", df.head())
    print(f"Encrypted column {columns} and saved to {output_csv}")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Nothing to Encrypt")
        sys.exit(0)
    else:
        # TODO: Encrypt a column
        encrypt_column("./landing/results.csv", "./output/results.csv", sys.argv[1:])
