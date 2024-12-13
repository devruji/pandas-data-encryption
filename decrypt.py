from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from utils.load_key import load_key

import base64
import numpy as np
import pandas as pd


# ?: Helper function to remove padding
def unpad(data: bytes) -> bytes:
    """
    The function `unpad` removes padding from data using PKCS7 padding scheme with a
    block size of 256. It creates an unpadder object with a block size of 256 bits,
    and then uses this unpadder object to unpad the input data.

    :param data: The input data that needs to be unpadded.
    :return: The function `unpad(data)` returns the unpadded data after removing
    padding using PKCS7 padding scheme with a block size of 256.
    """
    # ?: Create an unpadder object with a block size of 256 bits
    unpadder = padding.PKCS7(256).unpadder()

    # ?: Use the unpadder object to unpad the input data
    unpadded_data = unpadder.update(data) + unpadder.finalize()

    # ?: Return the unpadded data
    return unpadded_data


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
    import os
    import sys
    from dotenv import load_dotenv

    load_dotenv(".env.shared")
    load_dotenv(".env.secret")

    if len(sys.argv) == 1:
        print("Nothing to Decrypt")
        sys.exit(0)
    else:
        # ?: Decrypt columns
        decrypt_columns(
            input_csv=os.getenv("PATH_ENCRYPTED_CSV"),
            output_csv=os.getenv("PATH_DECRYPTED_CSV"),
            columns=sys.argv[1:],
        )
