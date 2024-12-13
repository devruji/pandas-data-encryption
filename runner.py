from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from utils.load_key import load_key

import os
import sys
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


def encrypt_column(input_csv: str, output_csv: str, columns: list[str]) -> None:
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


if __name__ == "__main__":
    from dotenv import load_dotenv

    load_dotenv(".env.secret")
    load_dotenv(".env.shared")

    if len(sys.argv) == 1:
        print("Nothing to Encrypt")
        sys.exit(0)
    else:
        # TODO: Encrypt a column
        encrypt_column(
            os.getenv("PATH_INPUT_CSV"), os.getenv("PATH_ENCRYPTED_CSV"), sys.argv[1:]
        )
