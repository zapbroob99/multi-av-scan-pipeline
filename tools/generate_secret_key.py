"""Generate a server key for encrypting integration credentials at rest."""

from cryptography.fernet import Fernet


if __name__ == "__main__":
    print(Fernet.generate_key().decode("ascii"))
