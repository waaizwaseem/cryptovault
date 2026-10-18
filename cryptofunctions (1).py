import hashlib
import os
import shutil
import subprocess


class CryptoError(Exception):
    pass


# CAESAR CIPHER

def caesar_encrypt(text, shift):

    encrypted_text = ""

    for character in text:
        if character.isupper():
            new_character = chr((ord(character) - ord("A") + shift) % 26 + ord("A"))
            encrypted_text += new_character

        elif character.islower():
            new_character = chr((ord(character) - ord("a") + shift) % 26 + ord("a"))
            encrypted_text += new_character

        else:
            encrypted_text += character

    return encrypted_text


def caesar_decrypt(text, shift):

    return caesar_encrypt(text, -shift)

# TRANSPOSITION CIPHER

def transposition_encrypt(text, key):

    if key <= 1:
        raise CryptoError("Transposition key must be greater than 1.")

    encrypted_text = ""

    for column in range(key):
        current_index = column

        while current_index < len(text):
            encrypted_text += text[current_index]
            current_index += key

    return encrypted_text


def transposition_decrypt(ciphertext, key):
    """
    Decrypts text encrypted by transposition_encrypt().
    """

    if key <= 1:
        raise CryptoError("Transposition key must be greater than 1.")

    text_length = len(ciphertext)

    base_column_length = text_length // key
    extra_characters = text_length % key

    column_lengths = []

    for column in range(key):
        if column < extra_characters:
            column_lengths.append(base_column_length + 1)
        else:
            column_lengths.append(base_column_length)

    columns = []
    start_index = 0

    for length in column_lengths:
        end_index = start_index + length
        columns.append(ciphertext[start_index:end_index])
        start_index = end_index

    decrypted_text = ""
    max_column_length = max(column_lengths) if column_lengths else 0

    for row in range(max_column_length):
        for column in range(key):
            if row < len(columns[column]):
                decrypted_text += columns[column][row]

    return decrypted_text


# ==========================================================
# AES / OPENSSL
# ==========================================================

def check_openssl_installed():
    """
    Checks whether OpenSSL is available in the current environment.

    Returns:
        True if OpenSSL is found.

    Raises:
        CryptoError if OpenSSL is not found.
    """

    openssl_path = shutil.which("openssl")

    if openssl_path is None:
        raise CryptoError(
            "OpenSSL was not found. AES/OpenSSL encryption may not work in Try Jupyter. "
            "Use local Python, VS Code, Kali Linux, or another environment with OpenSSL installed."
        )

    return True


def aes_encrypt_file(input_path, output_path, password):
    """
    Encrypts a file using AES-256-CBC through OpenSSL.

    Parameters:
        input_path: original file path
        output_path: encrypted output path
        password: AES password

    Returns:
        True if successful.
    """

    check_openssl_installed()

    if not os.path.exists(input_path):
        raise CryptoError(f"Input file does not exist: {input_path}")

    output_folder = os.path.dirname(output_path)

    if output_folder:
        os.makedirs(output_folder, exist_ok=True)

    command = [
        "openssl",
        "enc",
        "-aes-256-cbc",
        "-salt",
        "-pbkdf2",
        "-in",
        input_path,
        "-out",
        output_path,
        "-pass",
        f"pass:{password}"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise CryptoError(f"AES/OpenSSL encryption failed: {result.stderr}")

    return True


def aes_decrypt_file(input_path, output_path, password):
    """
    Decrypts a file encrypted using aes_encrypt_file().
    """

    check_openssl_installed()

    if not os.path.exists(input_path):
        raise CryptoError(f"Encrypted file does not exist: {input_path}")

    output_folder = os.path.dirname(output_path)

    if output_folder:
        os.makedirs(output_folder, exist_ok=True)

    command = [
        "openssl",
        "enc",
        "-d",
        "-aes-256-cbc",
        "-pbkdf2",
        "-in",
        input_path,
        "-out",
        output_path,
        "-pass",
        f"pass:{password}"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise CryptoError(
            "AES/OpenSSL decryption failed. The password may be wrong, "
            "or the file may not be a valid AES encrypted file."
        )

    return True


# ==========================================================
# HASHING / FILE FINGERPRINTING
# ==========================================================

def generate_sha256(file_path):
    """
    Generates SHA-256 fingerprint/hash of a file.

    SHA-256 is preferred for integrity checking.
    """

    if not os.path.exists(file_path):
        raise CryptoError(f"File does not exist: {file_path}")

    sha256_hash = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(4096)

            if not chunk:
                break

            sha256_hash.update(chunk)

    return sha256_hash.hexdigest()


def generate_md5(file_path):
    """
    Generates MD5 fingerprint/hash of a file.

    MD5 is included for comparison only.
    SHA-256 is better for real integrity checking.
    """

    if not os.path.exists(file_path):
        raise CryptoError(f"File does not exist: {file_path}")

    md5_hash = hashlib.md5()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(4096)

            if not chunk:
                break

            md5_hash.update(chunk)

    return md5_hash.hexdigest()


def save_hash_to_file(file_path, hash_output_path, hash_type="sha256"):
    """
    Saves a file fingerprint/hash to a separate .hash file.

    Used by menu option:
        Save file fingerprint
    """

    hash_type = hash_type.lower()

    if hash_type == "sha256":
        hash_value = generate_sha256(file_path)
    elif hash_type == "md5":
        hash_value = generate_md5(file_path)
    else:
        raise CryptoError("Unsupported hash type. Use 'sha256' or 'md5'.")

    output_folder = os.path.dirname(hash_output_path)

    if output_folder:
        os.makedirs(output_folder, exist_ok=True)

    with open(hash_output_path, "w", encoding="utf-8") as hash_file:
        hash_file.write(hash_value)

    return hash_value


def read_stored_hash(hash_file_path):
    """
    Reads a saved fingerprint/hash from a .hash file.
    """

    if not os.path.exists(hash_file_path):
        raise CryptoError(f"Hash file does not exist: {hash_file_path}")

    with open(hash_file_path, "r", encoding="utf-8") as hash_file:
        stored_hash = hash_file.read().strip()

    return stored_hash


def verify_file_integrity(file_path, stored_hash):
    """
    Verifies a file against a stored SHA-256 hash string.

    Returns:
        True if unchanged.
        False if modified.
    """

    current_hash = generate_sha256(file_path)

    return current_hash == stored_hash


def verify_file_integrity_from_hash_file(file_path, hash_file_path):
    """
    Verifies a file against a saved .hash file.

    Used by menu option:
        Verify file against saved fingerprint

    Returns:
        dictionary with stored hash, current hash, and validity status.
    """

    stored_hash = read_stored_hash(hash_file_path)
    current_hash = generate_sha256(file_path)

    is_valid = current_hash == stored_hash

    return {
        "file_path": file_path,
        "hash_file_path": hash_file_path,
        "stored_hash": stored_hash,
        "current_hash": current_hash,
        "is_valid": is_valid
    }


def compare_md5_and_sha256(file_path):
    """
    Generates both MD5 and SHA-256 for comparison.

    Used by menu option:
        Compare MD5 and SHA-256
    """

    return {
        "file_path": file_path,
        "md5": generate_md5(file_path),
        "sha256": generate_sha256(file_path)
    }


# ==========================================================
# DIFFIE-HELLMAN KEY EXCHANGE
# ==========================================================

def diffie_hellman_shared_key(prime_number, primitive_root, private_key_a, private_key_b):
    """
    Simulates Diffie-Hellman key exchange.

    Diffie-Hellman does not encrypt the file directly.
    It generates a shared secret key.

    Parameters:
        prime_number: public prime number p
        primitive_root: public primitive root g
        private_key_a: Alice's private key
        private_key_b: Bob's private key
    """

    if prime_number <= 1:
        raise CryptoError("Prime number must be greater than 1.")

    if primitive_root <= 1:
        raise CryptoError("Primitive root must be greater than 1.")

    if private_key_a <= 0 or private_key_b <= 0:
        raise CryptoError("Private keys must be positive integers.")

    public_key_a = pow(primitive_root, private_key_a, prime_number)
    public_key_b = pow(primitive_root, private_key_b, prime_number)

    shared_key_a = pow(public_key_b, private_key_a, prime_number)
    shared_key_b = pow(public_key_a, private_key_b, prime_number)

    return {
        "public_key_a": public_key_a,
        "public_key_b": public_key_b,
        "shared_key_a": shared_key_a,
        "shared_key_b": shared_key_b,
        "keys_match": shared_key_a == shared_key_b
    }


def diffie_hellman_caesar_shift(prime_number, primitive_root, private_key_a, private_key_b):
    """
    Generates a Caesar Cipher shift from a Diffie-Hellman shared key.

    Used by menu option:
        Encrypt with shared Diffie-Hellman key
    """

    result = diffie_hellman_shared_key(
        prime_number,
        primitive_root,
        private_key_a,
        private_key_b
    )

    if not result["keys_match"]:
        raise CryptoError("Diffie-Hellman shared keys do not match.")

    shift = result["shared_key_a"] % 26

    if shift == 0:
        shift = 1

    return shift


# ==========================================================
# TEST CODE FOR STUDENT 2
# ==========================================================

if __name__ == "__main__":
    print("Testing crypto_engine.py")

    sample_text = "HELLO WORLD"
    shift = 3

    print("\n--- Caesar Cipher Test ---")
    caesar_encrypted = caesar_encrypt(sample_text, shift)
    caesar_decrypted = caesar_decrypt(caesar_encrypted, shift)

    print("Original :", sample_text)
    print("Encrypted:", caesar_encrypted)
    print("Decrypted:", caesar_decrypted)

    print("\n--- Transposition Cipher Test ---")
    transposition_key = 3
    transposition_encrypted = transposition_encrypt(sample_text, transposition_key)
    transposition_decrypted = transposition_decrypt(transposition_encrypted, transposition_key)

    print("Original :", sample_text)
    print("Encrypted:", transposition_encrypted)
    print("Decrypted:", transposition_decrypted)

    print("\n--- Hashing Test ---")
    test_file_path = "test_hash_file.txt"

    with open(test_file_path, "w", encoding="utf-8") as test_file:
        test_file.write("This is a test file for CryptoVault hashing.")

    sha256_value = generate_sha256(test_file_path)
    md5_value = generate_md5(test_file_path)

    print("SHA-256:", sha256_value)
    print("MD5    :", md5_value)

    hash_file_path = "test_hash_file_sha256.hash"
    save_hash_to_file(test_file_path, hash_file_path, "sha256")

    integrity_before = verify_file_integrity_from_hash_file(
        test_file_path,
        hash_file_path
    )

    print("Integrity before modification:", integrity_before["is_valid"])

    with open(test_file_path, "a", encoding="utf-8") as test_file:
        test_file.write("\nThis line modifies the file.")

    integrity_after = verify_file_integrity_from_hash_file(
        test_file_path,
        hash_file_path
    )

    print("Integrity after modification :", integrity_after["is_valid"])

    print("\n--- Diffie-Hellman Test ---")
    dh_result = diffie_hellman_shared_key(23, 9, 4, 3)

    print("Alice public key:", dh_result["public_key_a"])
    print("Bob public key  :", dh_result["public_key_b"])
    print("Alice shared key:", dh_result["shared_key_a"])
    print("Bob shared key  :", dh_result["shared_key_b"])
    print("Keys match      :", dh_result["keys_match"])

    print("\n--- OpenSSL Availability Test ---")
    try:
        check_openssl_installed()
        print("OpenSSL is available.")
    except CryptoError as error:
        print(error)