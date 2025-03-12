import os
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

WALLET_DIR = "wallets"
if not os.path.exists(WALLET_DIR):
    os.makedirs(WALLET_DIR)

class Wallet:
    def __init__(self, user_id):
        self.user_id = str(user_id)
        self.wallet_path = os.path.join(WALLET_DIR, f"{self.user_id}.json")
        self.wallet_data = self.load_wallet()

    def load_wallet(self):
        """Carga la wallet desde un archivo JSON"""
        if os.path.exists(self.wallet_path):
            try:
                with open(self.wallet_path, "r") as file:
                    return json.load(file)
            except (json.JSONDecodeError, FileNotFoundError):
                print(f"⚠️ Error al cargar wallet de {self.user_id}.")
                return None
        return None

    def generate_keys(self):
        """Genera un par de claves RSA para la wallet."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        address = hashlib.sha256(public_pem).hexdigest()

        wallet_data = {
            "user_id": self.user_id,
            "address": address,
            "private_key": private_pem.decode(),
            "public_key": public_pem.decode()
        }

        with open(self.wallet_path, "w") as file:
            json.dump(wallet_data, file, indent=4)

        self.wallet_data = wallet_data
        print(f"✅ Wallet creada para {self.user_id} con dirección: {address}")
        return address

    def get_address(self):
        """Devuelve la dirección de la wallet."""
        return self.wallet_data.get("address") if self.wallet_data else None

    def sign_transaction(self, message):
        """Firma una transacción con la clave privada."""
        if not self.wallet_data:
            return None

        try:
            private_key = serialization.load_pem_private_key(
                self.wallet_data["private_key"].encode(),
                password=None
            )

            signature = private_key.sign(
                message.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )

            return signature.hex()
        except Exception as e:
            print(f"❌ Error al firmar la transacción: {e}")
            return None

    def get_public_key(self):
        """Devuelve la clave pública de la wallet."""
        return self.wallet_data.get("public_key") if self.wallet_data else None






