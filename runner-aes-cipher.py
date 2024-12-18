from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from typing import List

from utils.load_key import load_key

import os
import base64
import numpy as np
import pandas as pd


# ?: Helper function to apply padding
def pad(data: bytes) -> bytes:
    """
    Apply PKCS7 padding to the input data.

    This function applies PKCS7 padding to the input data using a block size of
    128 bits, which is necessary to ensure that the data is a multiple of the
    block size required for encryption algorithms.

    :param data: The input data that needs to be padded.
    :return: The padded data after applying PKCS7 padding with a block size of
    128 bits.
    """
    # ?: Create a padder object with a block size of 128 bits
    padder = padding.PKCS7(128).padder()

    # ?: Use the padder object to pad the input data
    padded_data = padder.update(data) + padder.finalize()

    # ?: Return the padded data
    return padded_data


# ?: Helper function to remove padding
def unpad(data: bytes) -> bytes:
    """
    The function `unpad` removes padding from data using PKCS7 padding scheme with a
    block size of 128. It creates an unpadder object with a block size of 128 bits,
    and then uses this unpadder object to unpad the input data.

    :param data: The input data that needs to be unpadded.
    :return: The function `unpad(data)` returns the unpadded data after removing
    padding using PKCS7 padding scheme with a block size of 128.
    """
    # ?: Create an unpadder object with a block size of 128 bits
    unpadder = padding.PKCS7(128).unpadder()

    # ?: Use the unpadder object to unpad the input data
    unpadded_data = unpadder.update(data) + unpadder.finalize()

    # ?: Return the unpadded data
    return unpadded_data


def encrypt_columns(input_csv: str, output_csv: str, columns: List[str]) -> None:
    """
    Encrypt specified columns in a CSV file using AES symmetric encryption.

    :param input_csv: The file path to the CSV file to read from.
    :param output_csv: The file path to the CSV file to write to.
    :param columns: List of column names to encrypt.
    :return: None
    """
    key = load_key()

    # ?: Load the CSV file
    dataframe = pd.read_csv(input_csv, sep=r"\|\,", engine="python")
    dataframe.columns = dataframe.columns.str.strip("|")
    dataframe = dataframe.map(
        lambda x: x.strip("|") if isinstance(x, str) else x
    ).replace("", np.nan)

    # ?: Encrypt the specified columns
    for column in columns:
        if column not in dataframe.columns:
            raise Exception(f"Column: {column} not found in dataset")

        encrypted_values = []
        for value in dataframe[column]:
            if pd.isna(value):
                encrypted_values.append(np.nan)
                continue

            iv = os.urandom(16)  # ?: AES block size is 16 bytes, so IV is 16 bytes
            cipher = Cipher(
                algorithms.AES(key), modes.GCM(iv), backend=default_backend()
            )
            encryptor = cipher.encryptor()

            padded_data = pad(str(value).encode())
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            tag = encryptor.tag  # ?: Extract the authentication tag

            # ?: Encode IV + encrypted data + tag as a base64 string
            encrypted_values.append(
                base64.b64encode(iv + encrypted_data + tag).decode()
            )

        # ?: Replace the column in the DataFrame with the encrypted data
        dataframe[column] = encrypted_values

    # ?: Save the encrypted CSV file
    dataframe.to_csv(output_csv, sep=",", encoding="utf-8", index=False)

    print(f"[INFO]: Column(s): {columns} encrypted and saved to: {output_csv}")


def decrypt_columns(input_csv: str, output_csv: str, columns: list[str]) -> None:
    """
    Decrypt specified columns in an encrypted CSV file using AES symmetric encryption
    and save the decrypted CSV to a new file.

    :param input_csv: The file path to the encrypted CSV file to read from.
    :param output_csv: The file path to the CSV file to write the decrypted data to.
    :param columns: List of column names to decrypt.
    :return: None
    """
    key = load_key()  # ?: Load the AES encryption key

    # ?: Read the encrypted CSV file
    df = pd.read_csv(input_csv, sep=",", encoding="utf-8")

    # ?: Decrypt the specified columns
    for column in columns:
        decrypted_column = []

        for encrypted_value in df[column]:
            if pd.isna(encrypted_value):
                decrypted_column.append(np.nan)
                continue
            # ?: Decode the base64 encoded value
            encrypted_data = base64.b64decode(encrypted_value)
            iv = encrypted_data[:16]  # ?: Extract the initialization vector
            tag = encrypted_data[-16:]  # ?: Extract the authentication tag
            encrypted_value = encrypted_data[16:-16]  # ?: Extract the encrypted data

            # ?: Setup the AES cipher with the key, IV, and tag
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(initialization_vector=iv, tag=tag),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()  # ?: Create a decryptor object

            # ?: Decrypt and unpad the data
            padded_data = decryptor.update(encrypted_value) + decryptor.finalize()
            decrypted_value = unpad(padded_data).decode()

            decrypted_column.append(decrypted_value)  # ?: Add to the decrypted column

        df[column] = decrypted_column  # ?: Replace column with decrypted data

    # ?: Save the decrypted CSV file
    df.to_csv(output_csv, index=False, encoding="utf-8")

    print(f"[INFO]: Column(s): {columns} decrypted and saved to {output_csv}")


if __name__ == "__main__":
    import sys

    from dotenv import load_dotenv

    load_dotenv(".env.secret")
    load_dotenv(".env.shared")

    if len(sys.argv) == 1:
        print("Nothing to Encrypt")
        sys.exit(0)
    else:
        match sys.argv[1]:
            case "encrypt":
                # ?: Encrypt a column
                encrypt_columns(
                    os.getenv("PATH_INPUT_CSV"),
                    os.getenv("PATH_ENCRYPTED_CSV"),
                    sys.argv[2:],
                )
            case "decrypt":
                # ?: Decrypt a column
                decrypt_columns(
                    os.getenv("PATH_ENCRYPTED_CSV"),
                    os.getenv("PATH_DECRYPTED_CSV"),
                    sys.argv[2:],
                )
            case _:
                raise Exception("Invalid command")
