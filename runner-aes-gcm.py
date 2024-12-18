import os
import base64
import numpy as np
import pandas as pd

from typing import List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from utils.load_key import load_key


def encrypt_columns(input_csv: str, output_csv: str, columns: List[str]) -> None:
    """
    Encrypt specified columns in a CSV file using AES-GCM symmetric encryption.

    :param input_csv: The file path to the CSV file to read from.
    :param output_csv: The file path to the CSV file to write to.
    :param columns: List of column names to encrypt.
    :return: None
    """
    key: bytes = load_key()  # ?: Load the AES encryption key
    aesgcm: AESGCM = AESGCM(key)  # ?: Setup the AES-GCM cipher
    nonce: bytes = os.urandom(
        int(os.getenv("NONCE_SIZE"))
    )  # ?: Generate a random nonce

    # ?: Load the CSV file
    dataframe: pd.DataFrame = pd.read_csv(input_csv, sep=r"\|\,", engine="python")
    dataframe.columns = dataframe.columns.str.strip("|")
    dataframe: pd.DataFrame = dataframe.map(
        lambda x: x.strip("|") if isinstance(x, str) else x
    ).replace("", np.nan)

    # ?: Encrypt the specified column(s)
    for column in columns:
        if column not in dataframe.columns:
            raise Exception(f"Column: {column} not found in dataset")

        encrypted_values = []
        for value in dataframe[column]:
            if pd.isna(value):
                encrypted_values.append(np.nan)
                continue

            encrypted_value = aesgcm.encrypt(
                nonce=nonce, data=str(value).encode(), associated_data=None
            )

            # ?: Encode the nonce and encrypted value
            encrypted_values.append(base64.b64encode(nonce + encrypted_value).decode())

        # ?: Replace the original column with the encrypted values
        dataframe[column] = encrypted_values

    # ?: Save the encrypted CSV file
    dataframe.to_csv(output_csv, sep=",", encoding="utf-8", index=False)

    print(f"[INFO]: Column(s): {columns} encrypted and saved to: {output_csv}")


def decrypt_columns(input_csv: str, output_csv: str, columns: List[str]) -> None:
    """
    Decrypt specified columns in an encrypted CSV file using AES-GCM symmetric encryption.

    :param input_csv: The file path to the encrypted CSV file to read from.
    :param output_csv: The file path to the CSV file to write the decrypted data to.
    :param columns: List of column names to decrypt.
    :return: None
    """
    key: bytes = load_key()  # ?: Load the AES encryption key
    aesgcm: AESGCM = AESGCM(key)  # ?: Setup the AES-GCM cipher
    nonce_size: int = int(os.getenv("NONCE_SIZE"))  # ?: Get the nonce size

    # ?: Read the encrypted CSV file
    dataframe: pd.DataFrame = pd.read_csv(input_csv, sep=",", encoding="utf-8")

    # ?: Decrypt the specified columns
    for column in columns:
        decrypted_column = []

        for encrypted_value in dataframe[column]:
            if pd.isna(encrypted_value):
                decrypted_column.append(np.nan)
                continue

            # ?: Decode the base64 encoded value
            encrypted_data = base64.b64decode(encrypted_value)

            # ?: Decrypt the data
            decrypted_column.append(
                aesgcm.decrypt(
                    nonce=encrypted_data[:nonce_size],
                    data=encrypted_data[nonce_size:],
                    associated_data=None,
                ).decode()
            )

        # ?: Replace a column with decrypted data
        dataframe[column] = decrypted_column

    # ?: Save the decrypted CSV file
    dataframe.to_csv(output_csv, index=False, encoding="utf-8")

    print(f"[INFO]: Column(s): {columns} decrypted and saved to {output_csv}")


if __name__ == "__main__":
    import sys

    from dotenv import load_dotenv

    load_dotenv(".env.secret")
    load_dotenv(".env.shared")

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
