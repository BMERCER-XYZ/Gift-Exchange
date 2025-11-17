#!/usr/bin/env python3
"""
Encrypt gift exchange assignments.

Reads public keys from assignments.json, performs a random gift assignment,
encrypts each assignment with the recipient's public key, and saves to encrypted_assignments.json
"""

import json
import random
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64

def load_public_keys(filename='assignments.json'):
    """Load public keys from JSON file"""
    with open(filename, 'r') as f:
        data = json.load(f)
    
    public_keys = {}
    for name, key_b64 in data.items():
        # Decode base64 to get DER format
        key_der = base64.b64decode(key_b64)
        
        public_keys[name] = serialization.load_der_public_key(
            key_der,
            backend=default_backend()
        )
    
    return public_keys

def create_assignments(names):
    """Create a random gift exchange assignment (Secret Santa style)"""
    # Ensure each person doesn't get assigned to themselves or create mutual assignments
    max_attempts = 1000
    for attempt in range(max_attempts):
        assignments = {}
        shuffled = names.copy()
        random.shuffle(shuffled)
        
        # Check that no one is assigned to themselves or mutually to each other
        valid = True
        for i, giver in enumerate(names):
            receiver = shuffled[i]
            # Check: giver != receiver (no self-assignment)
            if giver == receiver:
                valid = False
                break
            # Check: if giver -> receiver, then receiver should not -> giver
            if names.index(receiver) < len(names):
                receiver_gets = shuffled[names.index(receiver)]
                if receiver_gets == giver:
                    valid = False
                    break
        
        if valid:
            for i, giver in enumerate(names):
                assignments[giver] = shuffled[i]
            return assignments
    
    # Fallback if no valid assignment found
    raise ValueError("Could not create valid gift assignments after many attempts")

def encrypt_assignments(assignments, public_keys):
    """Encrypt each person's assignment with their public key"""
    encrypted = {}
    
    for person, assigned_to in assignments.items():
        # Message: "You are assigned to: [Name]"
        message = f"You are assigned to: {assigned_to}".encode('utf-8')
        
        # Encrypt with their public key
        ciphertext = public_keys[person].encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Encode as base64 for storage
        encrypted[person] = base64.b64encode(ciphertext).decode('utf-8')
    
    return encrypted

def main():
    print("Loading public keys from assignments.json...")
    public_keys = load_public_keys()
    names = list(public_keys.keys())
    
    print(f"Found {len(names)} people: {', '.join(names)}")
    
    print("\nCreating random gift assignments...")
    assignments = create_assignments(names)
    
    print("\nEncrypting assignments with public keys...")
    encrypted_assignments = encrypt_assignments(assignments, public_keys)
    
    print("Saving encrypted assignments to encrypted_assignments.json...")
    with open('encrypted_assignments.json', 'w') as f:
        json.dump(encrypted_assignments, f, indent=2)
    
    print("\n✓ Done! Encrypted assignments saved to encrypted_assignments.json")

if __name__ == '__main__':
    main()
