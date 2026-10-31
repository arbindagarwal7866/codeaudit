"""Password storage."""
import hashlib


def password_key(plain, salt):
    """Derive the value stored in users.password for this password."""
    return hashlib.sha1((salt + plain).encode()).hexdigest()


def check_password(password, salt, stored):
    return password_key(password, salt) == stored
