#!/usr/bin/env python3
# sender.py - Secure File Transfer Protocol (Sender)

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

# For ElGamal we'll use a custom implementation since it's not directly in cryptography
# Note: In real-world applications, use established libraries for ElGamal
from math import gcd
import random

# Constants
AES_KEY_SIZE = 32  # 256 bits
AES_BLOCK_SIZE = 16  # 128 bits
RSA_KEY_SIZE = 2048
CHUNK_SIZE = 4096  # Size for reading files in chunks
DEFAULT_PORT = 9999
BUFFER_SIZE = 8192

class ElGamalKeyPair:
    """Custom ElGamal implementation"""
    def __init__(self, prime_bits=1024, load_from=None):
        if load_from:
            # Load from existing keys
            self.p = load_from['p']
            self.g = load_from['g']
            self.x = load_from['x']
            self.y = pow(self.g, self.x, self.p)  # Public key
        else:
            # Generate new keys
            self.p = self._generate_large_prime(prime_bits)
            self.g = self._find_generator(self.p)
            self.x = random.randint(2, self.p - 2)  # Private key
            self.y = pow(self.g, self.x, self.p)  # Public key

    def _is_prime(self, n, k=40):
        """Miller-Rabin primality test"""
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False
        
        # Write n as 2^r·d + 1
        r, d = 0, n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
            
        # Witness loop
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True
    
    def _generate_large_prime(self, bits):
        """Generate a prime number of specified bit length"""
        while True:
            p = random.getrandbits(bits)
            p |= (1 << bits - 1) | 1  # Ensure the number is odd and has the right bit length
            if self._is_prime(p):
                return p
    
    def _find_generator(self, p):
        """Find a generator for Z_p^*"""
        if p == 2:
            return 1
        
        # Find prime factors of p-1
        phi = p - 1
        factors = []
        # For simplicity, we'll just check small factors and use a probabilistic approach
        for i in range(2, 100):
            if phi % i == 0:
                factors.append(i)
                while phi % i == 0:
                    phi //= i
        
        if phi > 1:
            factors.append(phi)
        
        # Find a generator
        while True:
            g = random.randint(2, p - 1)
            if all(pow(g, (p - 1) // factor, p) != 1 for factor in factors):
                return g
    
    def sign(self, hash_value):
        """Sign a hash value using ElGamal signature"""
        # Convert hash to int if it's bytes
        if isinstance(hash_value, bytes):
            hash_int = int.from_bytes(hash_value, byteorder='big') % self.p
        else:
            hash_int = hash_value % self.p
        
        # Choose k such that gcd(k, p-1) = 1
        while True:
            k = random.randint(2, self.p - 2)
            if gcd(k, self.p - 1) == 1:
                break
        
        # Calculate r = g^k mod p
        r = pow(self.g, k, self.p)
        
        # Calculate s = (hash - x*r) * k^-1 mod (p-1)
        k_inv = pow(k, -1, self.p - 1)
        s = (hash_int - self.x * r) * k_inv % (self.p - 1)
        
        return (r, s)
    
    def export_public_key(self):
        """Export the public key components"""
        return {
            'p': self.p,
            'g': self.g,
            'y': self.y
        }
    
    def export_private_key(self):
        """Export private key (for demonstration purposes only)"""
        return {
            'p': self.p,
            'g': self.g,
            'x': self.x
        }


class SecureFileSender:
    def __init__(self, receiver_host='localhost', receiver_port=DEFAULT_PORT, key_dir='keys', load_keys=True):
        """Initialize the secure file sender with keys and connection details"""
        self.receiver_host = receiver_host
        self.receiver_port = receiver_port
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(exist_ok=True)
        
        # Key paths
        self.rsa_private_key_path = self.key_dir / "sender_rsa_private.pem"
        self.rsa_public_key_path = self.key_dir / "sender_rsa_public.pem"
        self.elgamal_keys_path = self.key_dir / "sender_elgamal_keys.json"
        
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
            
            print("Génération des clés ElGamal...")
            self.elgamal_keys = ElGamalKeyPair(prime_bits=1024)
            
            # Save the newly generated keys
            self._save_keys()
        
        # We'll get the receiver's public key when we connect
        self.receiver_rsa_public_key = None
        
    def _keys_exist(self) -> bool:
        """Check if key files exist"""
        return (self.rsa_private_key_path.exists() and 
                self.rsa_public_key_path.exists() and 
                self.elgamal_keys_path.exists())
    
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
        
        # Save ElGamal keys
        with open(self.elgamal_keys_path, 'w') as f:
            json.dump(self.elgamal_keys.export_private_key(), f)
        
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
            
            # Load ElGamal keys
            with open(self.elgamal_keys_path, 'r') as f:
                elgamal_data = json.load(f)
            
            # Recreate ElGamal key pair
            self.elgamal_keys = ElGamalKeyPair(prime_bits=1024, load_from=elgamal_data)
            
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
            self.elgamal_keys = ElGamalKeyPair(prime_bits=1024)
            
            # Save the newly generated keys
            self._save_keys()
    
    def _generate_aes_key(self) -> bytes:
        """Generate a random AES key"""
        return os.urandom(AES_KEY_SIZE)
    
    def _encrypt_file_with_aes(self, file_path: str, aes_key: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt a file using AES in CBC mode
        Returns (iv, encrypted_data)
        """
        # Generate a random initialization vector
        iv = os.urandom(AES_BLOCK_SIZE)
        
        # Create an AES cipher
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv)
        )
        encryptor = cipher.encryptor()
        
        # Create padder
        padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
        
        try:
            # Read file and encrypt
            with open(file_path, 'rb') as f:
                encrypted_data = b''
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    # Pad the last chunk if needed
                    if len(chunk) < CHUNK_SIZE:
                        padded_chunk = padder.update(chunk) + padder.finalize()
                    else:
                        padded_chunk = padder.update(chunk)
                    
                    encrypted_chunk = encryptor.update(padded_chunk)
                    encrypted_data += encrypted_chunk
                
                # Finalize encryption
                if len(chunk) == CHUNK_SIZE:
                    # If the last chunk was full-sized, we need to add a padding block
                    encrypted_data += encryptor.update(padder.finalize())
                
                encrypted_data += encryptor.finalize()
                
            return iv, encrypted_data
        except Exception as e:
            print(f"Erreur lors du chiffrement du fichier : {e}")
            raise
    
    def _encrypt_with_rsa(self, data: bytes, public_key) -> bytes:
        """Encrypt data using RSA"""
        return public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def _hash_data(self, data: bytes) -> bytes:
        """Create a SHA-256 hash of the data"""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data)
        return digest.finalize()
    
    def connect_to_receiver(self):
        """
        Connect to the receiver and exchange public keys
        """
        try:
            # Create a socket connection
            print(f"Connexion au récepteur à l'adresse {self.receiver_host}:{self.receiver_port}...")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.receiver_host, self.receiver_port))
            
            # Serialize and send our public keys
            rsa_public_bytes = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            elgamal_public = self.elgamal_keys.export_public_key()
            
            # Prepare key exchange message
            keys_message = {
                'rsa_public_key': base64.b64encode(rsa_public_bytes).decode('utf-8'),
                'elgamal_public_key': elgamal_public
            }
            
            # Send our public keys
            self._send_json(keys_message)
            
            # Receive receiver's public key
            receiver_keys = self._receive_json()
            receiver_rsa_public_bytes = base64.b64decode(receiver_keys['rsa_public_key'])
            self.receiver_rsa_public_key = serialization.load_pem_public_key(receiver_rsa_public_bytes)
            
            print("Connexion réussie et échange des clés avec le récepteur terminé")
            return True
            
        except Exception as e:
            print(f"Erreur lors de la connexion au récepteur : {e}")
            if hasattr(self, 'socket'):
                self.socket.close()
            return False
    
    def _send_json(self, data: Dict):
        """Send JSON data over the socket"""
        json_data = json.dumps(data).encode('utf-8')
        length_prefix = len(json_data).to_bytes(4, byteorder='big')
        self.socket.sendall(length_prefix + json_data)
    
    def _receive_json(self) -> Dict:
        """Receive JSON data from the socket"""
        length_bytes = self.socket.recv(4)
        if not length_bytes:
            raise ConnectionError("Connexion fermée par le récepteur")
        
        length = int.from_bytes(length_bytes, byteorder='big')
        json_data = b''
        
        # Receive the JSON data in chunks
        remaining = length
        while remaining > 0:
            chunk = self.socket.recv(min(remaining, BUFFER_SIZE))
            if not chunk:
                raise ConnectionError("Connexion fermée par le récepteur")
            json_data += chunk
            remaining -= len(chunk)
        
        return json.loads(json_data.decode('utf-8'))
    
    def _send_bytes(self, data: bytes):
        """Send binary data over the socket"""
        length_prefix = len(data).to_bytes(8, byteorder='big')
        self.socket.sendall(length_prefix + data)
    
    def send_file(self, file_path: str) -> bool:
        """
        Send a file securely following the protocol:
        1. Encrypt file with AES
        2. Encrypt AES key with receiver's RSA public key
        3. Sign the hash of the encrypted data with ElGamal
        4. Encrypt everything again with RSA
        5. Send to receiver
        """
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                print(f"Erreur : Le fichier {file_path} n'existe pas")
                return False
            
            if not self.receiver_rsa_public_key:
                print("Erreur : Non connecté au récepteur")
                return False
            
            print(f"Préparation pour l'envoi du fichier : {file_path}")
            
            # Generate AES key for file encryption
            aes_key = self._generate_aes_key()
            
            # Encrypt the file with AES
            print("Chiffrement du fichier avec AES...")
            iv, encrypted_file = self._encrypt_file_with_aes(file_path, aes_key)
            
            # Encrypt the AES key with receiver's RSA public key
            print("Chiffrement de la clé AES avec RSA...")
            encrypted_aes_key = self._encrypt_with_rsa(aes_key, self.receiver_rsa_public_key)
            
            # Combine IV and encrypted file for hashing and signing
            data_to_sign = iv + encrypted_file
            
            # Create hash of the encrypted data
            print("Création du hash SHA-256...")
            data_hash = self._hash_data(data_to_sign)
            
            # Sign the hash with ElGamal
            print("Signature du hash avec ElGamal...")
            signature = self.elgamal_keys.sign(data_hash)
            
            # Prepare the complete message
            secure_message = {
                'filename': file_path.name,
                'iv': base64.b64encode(iv).decode('utf-8'),
                'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
                'signature': signature,
                # We'll send the encrypted file separately
            }
            
            # Final RSA encryption of the message
            # Since the message might be large, we'll encrypt it in chunks or just encrypt the metadata
            # and send the encrypted file separately
            print("Préparation du message sécurisé...")
            secure_message_json = json.dumps(secure_message).encode('utf-8')
            
            # For the final layer, we only encrypt the metadata with RSA
            # The file itself is already encrypted with AES
            encrypted_metadata = self._encrypt_with_rsa(
                secure_message_json[:min(len(secure_message_json), 190)],  # RSA size limitation
                self.receiver_rsa_public_key
            )
            
            # Prepare the final message with encrypted metadata and file
            final_message = {
                'encrypted_metadata': base64.b64encode(encrypted_metadata).decode('utf-8'),
                'metadata_remainder': base64.b64encode(secure_message_json[min(len(secure_message_json), 190):]).decode('utf-8')
            }
            
            # Send the message
            print("Envoi du message sécurisé au récepteur...")
            self._send_json(final_message)
            
            # Send the encrypted file separately
            print(f"Envoi du fichier chiffré ({len(encrypted_file)} octets)...")
            self._send_bytes(encrypted_file)
            
            print(f"Fichier {file_path} envoyé avec succès !")
            return True
            
        except Exception as e:
            print(f"Erreur lors de l'envoi du fichier : {e}")
            return False
        
    def close(self):
        """Close the connection"""
        if hasattr(self, 'socket'):
            try:
                self.socket.close()
                print("Connexion fermée")
            except:
                pass


def main():
    """Main function to run the sender"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Transfert de fichier sécurisé - Expéditeur')
    parser.add_argument('file', help='Fichier à envoyer')
    parser.add_argument('--host', default='localhost', help='Adresse du récepteur')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='Port du récepteur')
    parser.add_argument('--key-dir', default='keys', help='Répertoire pour stocker les clés')
    parser.add_argument('--new-keys', action='store_true', help='Générer de nouvelles clés même si des clés existantes sont présentes')
    
    args = parser.parse_args()
    
    sender = SecureFileSender(
        args.host, 
        args.port, 
        key_dir=args.key_dir, 
        load_keys=not args.new_keys
    )
    
    try:
        if sender.connect_to_receiver():
            sender.send_file(args.file)
    finally:
        sender.close()


if __name__ == "__main__":
    main()