import time
import base64

# Define a character set for decoding
CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

def is_key_valid(encrypted_key, base_key):
    _, shuffled_expiration = encrypted_key.split('|')

    # Unshuffle the expiration time
    expiration_time_str = unshuffle_digits(shuffled_expiration)
    current_time = int(time.time())
    return current_time < int(expiration_time_str)

def vigenere_decrypt(ciphertext, key):
    decrypted = []
    key_length = len(key)

    for i, char in enumerate(ciphertext):
        shift = ord(key[i % key_length])  # Use ASCII value for shift
        decrypted_char = chr((ord(char) - shift) % 256)  # Use modulo 256 for all byte values
        decrypted.append(decrypted_char)

    return ''.join(decrypted)

def unshuffle_digits(shuffled_expiration):
    unshuffled = []

    for i in range(len(shuffled_expiration)):
        original_digit = (int(shuffled_expiration[i]) - i) % 10  # Reverse addition logic
        unshuffled.append(str(original_digit))

    return ''.join(unshuffled[::-1])  # Return as a single string of digits, reversed back to original order

if __name__ == "__main__":
    # Prompt the user for the encryption key
    encrypted_key = input("Enter the encryption key: ")

    if is_key_valid(encrypted_key, encrypted_key.split('|')[0]):
        while True:
            file_path = input("Enter the path of the encrypted HTML file: ")

            try:
                with open(file_path, 'r', encoding='utf-8') as file:
                    encoded_content = file.read().strip()  # Read only Base64-encoded ciphertext

                    # Decode from Base64
                    ciphertext = base64.b64decode(encoded_content).decode('latin-1')

                decrypted_unicode_content = vigenere_decrypt(ciphertext, encrypted_key.split('|')[0])

                # Save decrypted content back to a fixed filename
                with open('decrypted-file.html', 'w', encoding='utf-8') as output_file:
                    output_file.write(decrypted_unicode_content)

                print("Successfully Decrypted. File: decrypted-file.html")
                break  # Exit loop if file is opened and processed successfully

            except FileNotFoundError:
                print("The file does not exist! Please try again.")
            except Exception as e:
                print(f"An error occurred: {e}. Please try again.")
    else:
        print("The decryption key has expired or is invalid. Cannot decrypt.")
