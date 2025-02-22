import secrets
import string


def generate_recovery_codes(code_length=10):
    characters = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(characters) for _ in range(code_length))
