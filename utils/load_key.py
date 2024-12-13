import os


def load_key() -> bytes:
    """
    The function `load_key` reads and returns the content of a binary file named
    specified by the parameter `key_name` located in the "./keys" directory.

    :param key_name: The name of the key file to read. Defaults to "DataKey.key".
    :return: The function `load_key()` is returning the content of the file
    "./keys/<key_name>" as a binary string.
    """
    # ?: Open the key file in binary read mode
    with open(f"./keys/{os.getenv('KEY_NAME')}", "rb") as key_file:
        # ?: Read the content of the key file
        key_content = key_file.read()

        # ?; Return the content of the key file
        return key_content
