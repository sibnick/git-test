from mnemonic import Mnemonic
import nacl.signing
import nacl.encoding
import bip32utils

def generate_ton_private_key_from_mnemonic(mnemonic, passphrase=""):
    # Generate seed from mnemonic
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic, passphrase=passphrase)

    # Derive the private key using BIP32
    bip32_root_key = bip32utils.BIP32Key.fromEntropy(seed)
    bip32_child_key = bip32_root_key.ChildKey(44 + bip32utils.BIP32_HARDEN) \
                                       .ChildKey(396 + bip32utils.BIP32_HARDEN) \
                                       .ChildKey(0 + bip32utils.BIP32_HARDEN) \
                                       .ChildKey(0) \
                                       .ChildKey(0)
    
    # Get the private key in 32 bytes format
    private_key = bip32_child_key.PrivateKey()

    # Convert to Ed25519 key format if necessary
    signing_key = nacl.signing.SigningKey(private_key[:32], encoder=nacl.encoding.RawEncoder)
    verify_key = signing_key.verify_key

    # Print private key and corresponding public key
    print("Private Key:", signing_key.encode(encoder=nacl.encoding.HexEncoder).decode())
    print("Public Key:", verify_key.encode(encoder=nacl.encoding.HexEncoder).decode())

# Example mnemonic, typically you'll get this securely and keep it private
mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
generate_ton_private_key_from_mnemonic(mnemonic)

