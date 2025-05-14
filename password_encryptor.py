# password_encryptor.py

import bcrypt
# No need for typing.Union for these simple functions

def hash_password_bcrypt(password: str) -> bytes:
    """
    Hashes a password using bcrypt with a built-in salt.

    Args:
        password: The plain text password string.

    Returns:
        The hashed password as bytes. The salt is included in the hash.
    """
    # Ensure password is treated as bytes for bcrypt
    password_bytes = password.encode('utf-8')
    # bcrypt.gensalt() generates a salt and combines it with the hash function work factor
    # bcrypt.hashpw takes the password (as bytes) and the salt (as bytes)
    # The result is a bytes string containing the algorithm, cost, salt, and hash
    salt = bcrypt.gensalt()
    hashed_bytes = bcrypt.hashpw(password_bytes, salt)
    return hashed_bytes

def check_password_bcrypt(password_attempt: str, hashed_password: bytes) -> bool:
    """
    Verifies a plain text password attempt against a bcrypt hash.

    Args:
        password_attempt: The plain text password string the user entered.
        hashed_password: The stored bcrypt hash (as bytes).

    Returns:
        True if the password attempt matches the hash, False otherwise.
    """
    # Ensure password attempt is treated as bytes for bcrypt
    password_attempt_bytes = password_attempt.encode('utf-8')
    # bcrypt.checkpw handles the salt extraction and rehashing automatically
    try:
        return bcrypt.checkpw(password_attempt_bytes, hashed_password)
    except ValueError:
        # Handle cases where the hashed_password might not be a valid bcrypt hash
        # (e.g., empty string, incorrect format). Return False.
        return False


if __name__ == "__main__":
    # Example Usage (for testing the module directly)
    test_password = "mysecretpassword123"
    print(f"Original Password: {test_password}")

    hashed = hash_password_bcrypt(test_password)
    print(f"BCrypt Hash (bytes): {hashed}")
    print(f"BCrypt Hash (decoded): {hashed.decode('utf-8')}") # Often stored/displayed as string

    # Simulate checking
    is_correct = check_password_bcrypt(test_password, hashed)
    print(f"Checking '{test_password}' against hash: {is_correct}")

    wrong_password = "wrongpassword"
    is_correct_wrong = check_password_bcrypt(wrong_password, hashed)
    print(f"Checking '{wrong_password}' against hash: {is_correct_wrong}")

    # Note: The hash output includes the salt and work factor,
    # so you only need to store this single value (`hashed_bytes`).
    # bcrypt.checkpw knows how to extract the salt from the hash.