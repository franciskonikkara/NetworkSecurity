import numpy as np



def caesar_str_enc(plaintext, k):
    ciphertext = ""
    for ch in plaintext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            ciphertext += chr((ord(ch) - base + k) % 26 + base)
        else:
            ciphertext += ch
    return ciphertext


def caesar_str_dec(ciphertext, k):
    plaintext = ""
    for ch in ciphertext:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            plaintext += chr((ord(ch) - base - k) % 26 + base)
        else:
            plaintext += ch
    return plaintext


def vigenere_enc(keyword, plaintext):
    keyword = keyword.upper()
    plaintext = plaintext.upper()

    ciphertext = ""
    key_length = len(keyword)

    for i in range(len(plaintext)):
        p = ord(plaintext[i]) - ord('A')
        k = ord(keyword[i % key_length]) - ord('A')
        c = (p + k) % 26
        ciphertext += chr(c + ord('A'))

    return ciphertext


def vigenere_dec(keyword, ciphertext):
    keyword = keyword.upper()
    ciphertext = ciphertext.upper()

    plaintext = ""
    key_length = len(keyword)

    for i in range(len(ciphertext)):
        c = ord(ciphertext[i]) - ord('A')
        k = ord(keyword[i % key_length]) - ord('A')
        p = (c - k) % 26
        plaintext += chr(p + ord('A'))

    return plaintext


def test_function():
    print("Running extra tests...")
    return None


if __name__ == "__main__":

    input_str = 'test string'
    k = 3

    # Part 1 - Caesar
    encstr = caesar_str_enc(input_str, k)
    print("Caesar Encrypted:", encstr)

    decstr = caesar_str_dec(encstr, k)
    print("Caesar Decrypted:", decstr)

    test_function()

    # Part 2 - Vigenere
    input_key = 'keyword'

    encstr = vigenere_enc(input_key, input_str)
    print(f"Vigenere Ciphertext: {encstr}")

    decstr = vigenere_dec(input_key, encstr)

    print(f"Vigenere Decryptedtext: {decstr}")
