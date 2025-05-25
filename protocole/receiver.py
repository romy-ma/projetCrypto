#!/usr/bin/env python3
# receiver.py - Secure File Transfer Protocol (Receiver)

import os
import sys
import json
import base64
import socket
import hashlib
from pathlib import Path
from typing import Dict, Tuple, Union, Any

# Cryptographic libraries
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils as asym_utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.exceptions import InvalidSignature

# Constants
AES_KEY_SIZE = 32  # 256 bits
AES_BLOCK_SIZE = 16  # 128 bits
RSA_KEY_SIZE = 2048
CHUNK_SIZE = 4096  # Size for reading files in chunks
DEFAULT_PORT = 9999
BUFFER_SIZE = 8192
DOWNLOADS_DIR = Path("received_files")

class ElGamalPublicKey:
    """ElGamal public key for verification"""
    def __init__(self, p, g, y):
        self.p = p
        self.g = g
        self.y = y
    
    def verify(self, hash_value, signature):
        """Verify an ElGamal signature"""
        # Convert hash to int if it's bytes
        if isinstance(hash_value, bytes):
            hash_int = int.from_bytes(hash_value, byteorder='big') % self.p
        else:
            hash_int = hash_value % self.p
        
        r, s = signature
        
        # Check that 0 < r < p
        if r <= 0 or r >= self.p:
            return False
        
        # Verify the signature: g^hash ≡ y^r * r^s (mod p)
        left = pow(self.g, hash_int, self.p)
        right = (pow(self.y, r, self.p) * pow(r, s, self.p)) % self.p
        
        return left == right


class SecureFileReceiver:
    def __init__(self, port=DEFAULT_PORT, key_dir='keys', load_keys=True):
        """Initialize the secure file receiver with keys and server settings"""
        self.port = port
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(exist_ok=True)
        
        # Ensure downloads directory exists
        DOWNLOADS_DIR.mkdir(exist_ok=True)
        
        # Key paths
        self.rsa_private_key_path = self.key_dir / "receiver_rsa_private.pem"
        self.rsa_public_key_path = self.key_dir / "receiver_rsa_public.pem"
        
        # Try to load existing keys if requested
        if load_keys and self._keys_exist():
            print("Chargement des clés existantes...")
            self._load_keys()
        else:
            # Generate new keys
            print("Génération des clés RSA...")
            self.rsa_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=RSA_KEY_SIZE
            )
            self.rsa_public_key = self.rsa_private_key.public_key()
            
            # Save the newly generated keys
            self._save_keys()
        
        # We'll get the sender's public keys when they connect
        self.sender_rsa_public_key = None
        self.sender_elgamal_public_key = None
    
    def _keys_exist(self) -> bool:
        """Check if key files exist"""
        return (self.rsa_private_key_path.exists() and 
                self.rsa_public_key_path.exists())
    
    def _save_keys(self):
        """Save keys to files"""
        # Save RSA private key
        with open(self.rsa_private_key_path, 'wb') as f:
            f.write(self.rsa_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save RSA public key
        with open(self.rsa_public_key_path, 'wb') as f:
            f.write(self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        print(f"Clés sauvegardées dans {self.key_dir}")
    
    def _load_keys(self):
        """Load keys from files"""
        try:
            # Load RSA private key
            with open(self.rsa_private_key_path, 'rb') as f:
                self.rsa_private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            
            # Get RSA public key from private key
            self.rsa_public_key = self.rsa_private_key.public_key()
            
            print("Clés chargées avec succès")
        except Exception as e:
            print(f"Erreur lors du chargement des clés : {e}")
            print("Génération de nouvelles clés à la place...")
            
            # Generate new keys
            self.rsa_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=RSA_KEY_SIZE
            )
            self.rsa_public_key = self.rsa_private_key.public_key()
            
            # Save the newly generated keys
            self._save_keys()
    
    def _decrypt_with_rsa(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using RSA private key"""
        return self.rsa_private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def _decrypt_file_with_aes(self, encrypted_data: bytes, iv: bytes, aes_key: bytes) -> bytes:
        """Decrypt file data using AES in CBC mode"""
        # Create AES cipher
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv)
        )
        decryptor = cipher.decryptor()
        
        # Create unpadder
        unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
        
        # Decrypt the data
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
        
        return unpadded_data
    
    def _hash_data(self, data: bytes) -> bytes:
        """Create a SHA-256 hash of the data"""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()
    
    def start_server(self):
        """Start the server to listen for connections"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            
            print(f"Serveur démarré. Écoute sur le port {self.port}")
            
            while True:
                print("En attente d'une connexion...")
                client_socket, client_address = self.server_socket.accept()
                print(f"Connexion établie avec {client_address[0]}:{client_address[1]}")
                
                # Handle the connection
                try:
                    self.handle_client(client_socket)
                except Exception as e:
                    print(f"Erreur lors de la gestion du client : {e}")
                finally:
                    client_socket.close()
                    
        except KeyboardInterrupt:
            print("\nArrêt du serveur...")
        except Exception as e:
            print(f"Erreur du serveur : {e}")
        finally:
            if hasattr(self, 'server_socket'):
                self.server_socket.close()
    
    def _send_json(self, client_socket, data: Dict):
        """Send JSON data over the socket"""
        json_data = json.dumps(data).encode('utf-8')
        length_prefix = len(json_data).to_bytes(4, byteorder='big')
        client_socket.sendall(length_prefix + json_data)
    
    def _receive_json(self, client_socket) -> Dict:
        """Receive JSON data from the socket"""
        length_bytes = client_socket.recv(4)
        if not length_bytes:
            raise ConnectionError("Connexion fermée par l'expéditeur")
        
        length = int.from_bytes(length_bytes, byteorder='big')
        json_data = b''
        
        # Receive the JSON data in chunks
        remaining = length
        while remaining > 0:
            chunk = client_socket.recv(min(remaining, BUFFER_SIZE))
            if not chunk:
                raise ConnectionError("Connexion fermée par l'expéditeur")
            json_data += chunk
            remaining -= len(chunk)
        
        return json.loads(json_data.decode('utf-8'))
    
    def _receive_bytes(self, client_socket) -> bytes:
        """Receive binary data from the socket"""
        length_bytes = client_socket.recv(8)
        if not length_bytes:
            raise ConnectionError("Connexion fermée par l'expéditeur")
        
        length = int.from_bytes(length_bytes, byteorder='big')
        data = b''
        
        # Receive the data in chunks
        remaining = length
        while remaining > 0:
            chunk = client_socket.recv(min(remaining, BUFFER_SIZE))
            if not chunk:
                raise ConnectionError("Connexion fermée par l'expéditeur")
            data += chunk
            remaining -= len(chunk)
        
        return data
    
    def handle_client(self, client_socket):
        """Handle a client connection"""
        try:
            # Exchange public keys
            sender_keys = self._receive_json(client_socket)
            
            # Parse sender's RSA public key
            sender_rsa_public_bytes = base64.b64decode(sender_keys['rsa_public_key'])
            self.sender_rsa_public_key = serialization.load_pem_public_key(sender_rsa_public_bytes)
            
            # Parse sender's ElGamal public key
            elgamal_public = sender_keys['elgamal_public_key']
            self.sender_elgamal_public_key = ElGamalPublicKey(
                p=elgamal_public['p'],
                g=elgamal_public['g'],
                y=elgamal_public['y']
            )
            
            # Send our RSA public key
            rsa_public_bytes = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            response = {
                'rsa_public_key': base64.b64encode(rsa_public_bytes).decode('utf-8')
            }
            
            self._send_json(client_socket, response)
            
            print("Échange des clés terminé. En attente du fichier...")
            
            # Receive the file
            self.receive_file(client_socket)
            
        except Exception as e:
            print(f"Erreur dans la gestion du client : {e}")
            raise
    
    def receive_file(self, client_socket):
        """
        Receive and process an encrypted file following the protocol:
        1. Receive encrypted message
        2. Decrypt outer RSA layer
        3. Verify ElGamal signature
        4. Decrypt AES key with our RSA private key
        5. Decrypt file with AES
        6. Save the file
        """
        try:
            # Receive the encrypted message
            encrypted_message = self._receive_json(client_socket)
            
            # Decrypt the metadata with our RSA private key
            encrypted_metadata = base64.b64decode(encrypted_message['encrypted_metadata'])
            decrypted_metadata_part = self._decrypt_with_rsa(encrypted_metadata)
            
            # Get the remainder of the metadata (unencrypted)
            metadata_remainder = base64.b64decode(encrypted_message['metadata_remainder'])
            
            # Combine the parts
            secure_message_json = decrypted_metadata_part + metadata_remainder
            secure_message = json.loads(secure_message_json.decode('utf-8'))
            
            # Extract message components
            filename = secure_message['filename']
            iv = base64.b64decode(secure_message['iv'])
            encrypted_aes_key = base64.b64decode(secure_message['encrypted_aes_key'])
            signature = tuple(secure_message['signature'])  # (r, s)
            
            print(f"Réception du fichier : {filename}")
            
            # Receive the encrypted file data
            print("Réception des données du fichier chiffré...")
            encrypted_file = self._receive_bytes(client_socket)
            
            # Data to verify signature
            data_to_verify = iv + encrypted_file
            
            # Create hash of the encrypted data
            data_hash = self._hash_data(data_to_verify)
            
            # Verify ElGamal signature
            print("Vérification de la signature ElGamal...")
            if not self.sender_elgamal_public_key.verify(data_hash, signature):
                print("ERREUR : Échec de la vérification de signature ! Le fichier peut avoir été altéré.")
                return False
            
            print("Signature vérifiée avec succès !")
            
            # Decrypt the AES key with our RSA private key
            print("Déchiffrement de la clé AES...")
            aes_key = self._decrypt_with_rsa(encrypted_aes_key)
            
            # Decrypt the file with AES
            print("Déchiffrement du fichier avec AES...")
            decrypted_file = self._decrypt_file_with_aes(encrypted_file, iv, aes_key)
            
            # Save the file
            output_path = DOWNLOADS_DIR / filename
            with open(output_path, 'wb') as f:
                f.write(decrypted_file)
            
            print(f"Fichier sauvegardé avec succès dans {output_path}")
            return True
            
        except Exception as e:
            print(f"Erreur lors de la réception du fichier : {e}")
            return False


def main():
    """Main function to run the receiver"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Transfert de fichier sécurisé - Récepteur')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port du serveur')
    parser.add_argument('--key-dir', default='keys', help='Répertoire pour stocker les clés')
    parser.add_argument('--new-keys', action='store_true', help='Générer de nouvelles clés même si des clés existantes sont présentes')
    
    args = parser.parse_args()
    
    receiver = SecureFileReceiver(
        args.port, 
        key_dir=args.key_dir, 
        load_keys=not args.new_keys
    )
    receiver.start_server()


if __name__ == "__main__":
    main()