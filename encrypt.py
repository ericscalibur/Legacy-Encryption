import time
import base64
import re

# Define a character set for encoding
CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def generate_time_sensitive_key(base_key, validity_period):
    current_time = int(time.time())
    expiration_time = current_time + validity_period
    # Shuffle the expiration time
    shuffled_expiration = shuffle_digits(str(expiration_time))
    encrypted_key = f"{base_key}|{shuffled_expiration}"
    return encrypted_key

def vigenere_encrypt(plaintext, key):
    encrypted = []
    key_length = len(key)

    for i, char in enumerate(plaintext):
        shift = ord(key[i % key_length])  # Use ASCII value for shift
        encrypted_char = chr((ord(char) + shift) % 256)  # Use modulo 256 for all byte values
        encrypted.append(encrypted_char)

    return ''.join(encrypted)

def shuffle_digits(expiration_time):
    # Step 1: Reverse the order of the digits
    digits = list(expiration_time)[::-1]
    shuffled = []

    # Step 2 and 3: Add each digit to its index and take % 10
    for i in range(len(digits)):
        new_digit = (int(digits[i]) + i) % 10  # Ensure it's still a single digit
        shuffled.append(str(new_digit))  # Convert back to string

    return ''.join(shuffled)  # Join the list into a single string of digits

if __name__ == "__main__":
    while True:
        base_key = input("Enter the base encryption key: ")
        if re.search(r'[^a-zA-Z]', base_key):
            print("The base key contains invalid characters. Please use only letters.")
        else:
            break

    # Prompt for desired validity period in minutes
    validity_minutes = int(input("Enter the desired validity period in minutes: "))
    validity_period = validity_minutes * 60  # Convert minutes to seconds

    # Generate time-sensitive key
    encrypted_key = generate_time_sensitive_key(base_key, validity_period)

    while True:
        file_path = input("Enter the path of the HTML file to encrypt: ")

        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                plaintext = file.read()
            break  # Exit loop if file is opened successfully

        except FileNotFoundError:
            print("The file does not exist! Please try again.")

    # Encrypt using Vigenère cipher
    encrypted_content = vigenere_encrypt(plaintext, base_key)

    # Encode encrypted content in Base64
    encoded_content = base64.b64encode(encrypted_content.encode('latin-1')).decode('latin-1')

    # Save only the Base64-encoded encrypted content to the output file
    with open('encrypted-file.html', 'w', encoding='utf-8') as file:
        file.write(encoded_content)  # Store only Base64-encoded ciphertext

    print("Successful Encryption. File: encrypted-file.html")
    print("Full Encrypted Key for Decryption:")
    print(encrypted_key)  # Print the encryption key to the user
