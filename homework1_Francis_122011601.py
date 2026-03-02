import numpy as np

UID = 122011601                                        # Your UID should be included in your program as a global variable
Last_Name = 'Konikkara'                      # Your Last Name should be included in your program as a global variable
First_Name = 'Francis'                    # Your First Name should be included in your program as a global variable


def caesar_str_enc(plaintext, k):
    # Convert to uppercase and remove all whitespace
    plaintext = plaintext.upper().replace(' ', '')
    ciphertext = []
    for ch in plaintext:
        if ch.isalpha():
            ciphertext.append(chr((ord(ch) - ord('A') + k) % 26 + ord('A')))
        else:
            ciphertext.append(ch)
    return ''.join(ciphertext)                    # Returns a string


def caesar_str_dec(ciphertext, k):
    # Convert to uppercase and remove all whitespace
    ciphertext = ciphertext.upper().replace(' ', '')
    plaintext = []
    for ch in ciphertext:
        if ch.isalpha():
            plaintext.append(chr((ord(ch) - ord('A') - k) % 26 + ord('A')))
        else:
            plaintext.append(ch)
    return ''.join(plaintext)                     # Returns a string


def vigenere_enc(keyword, plaintext):
    # Convert both to uppercase and strip spaces
    plaintext = plaintext.upper().replace(' ', '')
    keyword = keyword.upper().replace(' ', '')

    ciphertext = []
    key_len = len(keyword)
    key_idx = 0
    for ch in plaintext:
        if ch.isalpha():
            shift = ord(keyword[key_idx % key_len]) - ord('A')
            ciphertext.append(chr((ord(ch) - ord('A') + shift) % 26 + ord('A')))
            key_idx += 1
        else:
            ciphertext.append(ch)
    return ''.join(ciphertext)


def vigenere_dec(keyword, ciphertext):
    # Convert both to uppercase and strip spaces
    ciphertext = ciphertext.upper().replace(' ', '')
    keyword = keyword.upper().replace(' ', '')

    plaintext = []
    key_len = len(keyword)
    key_idx = 0
    for ch in ciphertext:
        if ch.isalpha():
            shift = ord(keyword[key_idx % key_len]) - ord('A')
            plaintext.append(chr((ord(ch) - ord('A') - shift) % 26 + ord('A')))
            key_idx += 1
        else:
            plaintext.append(ch)
    return ''.join(plaintext)


def test_function():
    print("=" * 55)
    print("CAESAR CIPHER TESTS")
    print("=" * 55)

    # Exact examples from assignment spec
    assert caesar_str_enc('A TEST SENTENCE', 2) == 'CVGUVUGPVGPEG', \
        f"Spec example failed: got {caesar_str_enc('A TEST SENTENCE', 2)}"
    assert caesar_str_dec('CVGUVUGPVGPEG', 2) == 'ATESTSENTENCE', \
        f"Spec example failed: got {caesar_str_dec('CVGUVUGPVGPEG', 2)}"
    print("PASS: Spec examples (spaces stripped, uppercase output)")

    # Spaces and case handling
    assert caesar_str_enc('test string', 3) == 'WHVWVWULQJ', "Lowercase + spaces failed"
    assert caesar_str_enc('Test String', 3) == 'WHVWVWULQJ', "Mixed case + spaces failed"
    assert caesar_str_enc('TESTSTRING', 3) == 'WHVWVWULQJ', "Already clean input failed"
    print("PASS: Spaces removed and input uppercased before encryption")

    # Whitespace handling — output must NEVER contain spaces
    ws_variants = ['HELLO WORLD', 'hello world', '  HELLO   WORLD  ', 'Hello   World']
    for variant in ws_variants:
        result_enc = caesar_str_enc(variant, 5)
        assert ' ' not in result_enc, \
            f"Space found in caesar_str_enc output for input '{variant}': '{result_enc}'"
        assert result_enc == caesar_str_enc('HELLOWORLD', 5), \
            f"Whitespace input gave different result than clean input for '{variant}'"
    result_dec = caesar_str_dec('HELLO WORLD', 5)
    assert ' ' not in result_dec, \
        f"Space found in caesar_str_dec output: '{result_dec}'"
    assert result_dec == caesar_str_dec('HELLOWORLD', 5), \
        "caesar_str_dec: spaced vs clean input gave different results"
    print("PASS: Whitespace ignored — output always space-free (single, multiple, leading/trailing spaces)")

    # Wrap-around
    assert caesar_str_enc('XYZ', 3) == 'ABC', "Uppercase wrap-around failed"
    assert caesar_str_dec('ABC', 3) == 'XYZ', "Uppercase wrap-around decrypt failed"
    print("PASS: Wrap-around at end of alphabet")

    # Zero and full 26-shift (identity)
    assert caesar_str_enc('HELLO', 0) == 'HELLO', "Zero shift failed"
    assert caesar_str_enc('HELLO', 26) == 'HELLO', "26-shift failed"
    assert caesar_str_dec('HELLO', 0) == 'HELLO', "Zero shift decrypt failed"
    assert caesar_str_dec('HELLO', 26) == 'HELLO', "26-shift decrypt failed"
    print("PASS: Zero shift and full 26-shift (identity)")

    # Negative shift
    assert caesar_str_enc('DEF', -3) == 'ABC', "Negative shift encrypt failed"
    assert caesar_str_dec('ABC', -3) == 'DEF', "Negative shift decrypt failed"
    print("PASS: Negative shift")

    # ROT-13 self-inverse
    assert caesar_str_dec(caesar_str_enc('ROT THIRTEEN', 13), 13) == 'ROTTHIRTEEN', \
        "ROT-13 round-trip failed"
    print("PASS: ROT-13 self-inverse round-trip")

    # Round-trip for various k values
    msg = 'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG'
    clean = 'THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG'
    for k in [1, 7, 13, 19, 25]:
        assert caesar_str_dec(caesar_str_enc(msg, k), k) == clean, \
            f"Round-trip failed for k={k}"
    print("PASS: Round-trip for k = 1, 7, 13, 19, 25")

    print()
    print("=" * 55)
    print("VIGENERE CIPHER TESTS")
    print("=" * 55)

    # Exact examples from assignment spec
    assert vigenere_enc('KEY', 'Test String') == 'DIQDWRBMLQ', \
        f"Spec example failed: got {vigenere_enc('KEY', 'Test String')}"
    assert vigenere_dec('KEY', 'DIQDWRBMLQ') == 'TESTSTRING', \
        f"Spec example failed: got {vigenere_dec('KEY', 'DIQDWRBMLQ')}"
    print("PASS: Spec examples (vigenere_enc/dec with spaces and mixed case)")

    # Lowercase normalization
    assert vigenere_enc('key', 'test string') == 'DIQDWRBMLQ', "Lowercase keyword + plaintext failed"
    assert vigenere_dec('key', 'diqdwrbmlq') == 'TESTSTRING', "Lowercase ciphertext decrypt failed"
    print("PASS: Lowercase inputs normalized to uppercase, spaces stripped")

    # Whitespace handling — output must NEVER contain spaces
    ws_variants_vig = ['HELLO WORLD', 'hello world', '  HELLO   WORLD  ', 'Hello   World']
    for variant in ws_variants_vig:
        result_enc = vigenere_enc('KEY', variant)
        assert ' ' not in result_enc, \
            f"Space found in vigenere_enc output for input '{variant}': '{result_enc}'"
        assert result_enc == vigenere_enc('KEY', 'HELLOWORLD'), \
            f"Whitespace input gave different result than clean input for '{variant}'"
    result_dec = vigenere_dec('KEY', 'RIJVS UYVJN')
    assert ' ' not in result_dec, \
        f"Space found in vigenere_dec output: '{result_dec}'"
    assert result_dec == vigenere_dec('KEY', 'RIJVSUYVJN'), \
        "vigenere_dec: spaced vs clean ciphertext gave different results"
    print("PASS: Whitespace ignored — output always space-free (single, multiple, leading/trailing spaces)")

    # Known answer test
    assert vigenere_enc('KEY', 'HELLOWORLD') == 'RIJVSUYVJN', "Known answer (HELLOWORLD) failed"
    assert vigenere_dec('KEY', 'RIJVSUYVJN') == 'HELLOWORLD', "Known answer decrypt (HELLOWORLD) failed"
    print("PASS: Known answer test (KEY / HELLOWORLD -> RIJVSUYVJN)")

    # Keyword shorter than plaintext (repeats)
    assert vigenere_dec('AB', vigenere_enc('AB', 'ABCDEF')) == 'ABCDEF', "Short keyword round-trip failed"
    print("PASS: Keyword shorter than plaintext (repeats correctly)")

    # Keyword longer than plaintext
    enc = vigenere_enc('LONGERKEYWORD', 'HI')
    assert vigenere_dec('LONGERKEYWORD', enc) == 'HI', "Longer keyword failed"
    print("PASS: Keyword longer than plaintext")

    # Wrap-around
    assert vigenere_enc('B', 'Z') == 'A', "Vigenere wrap-around encrypt failed"
    assert vigenere_dec('B', 'A') == 'Z', "Vigenere wrap-around decrypt failed"
    print("PASS: Alphabet wrap-around (Z + B = A)")

    # Round-trip for various keywords with spaces in input
    msg_with_spaces = 'THE QUICK BROWN FOX'
    clean_msg = 'THEQUICKBROWNFOX'
    for kw in ['A', 'KEY', 'CRYPTO', 'VIGENERE', 'ZYXWVUTSRQPONMLKJIHGFEDCBA']:
        assert vigenere_dec(kw, vigenere_enc(kw, msg_with_spaces)) == clean_msg, \
            f"Round-trip failed for keyword={kw}"
    print("PASS: Round-trip for various keywords (with spaces in original input)")

    print()
    print("ALL TESTS PASSED!")
    print("=" * 55)
    return None


if __name__ == "__main__":
    input_str = 'Test String'
    k = 3

    # Part 1 - Caesar
    encstr = caesar_str_enc(input_str, k)
    print(f"Encrypted: {encstr}")
    decstr = caesar_str_dec(encstr, k)
    print(f"Decrypted: {decstr}")

    # Part 2 - Vigenere
    input_key = 'KEY'
    encstr = vigenere_enc(input_key, input_str)
    print(f"Ciphertext: {encstr}")
    decstr = vigenere_dec(input_key, encstr)
    print(f"Decryptedtext: {decstr}")

    # Run tests
    test_function()
