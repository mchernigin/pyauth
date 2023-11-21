import bcrypt


def hash_password(passord: bytes) -> bytes:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(passord, salt)
