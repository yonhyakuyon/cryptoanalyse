def clean_text(text):
    """Очистка текста: оставляет только русские буквы, заменяет Ё на Е"""
    text = text.upper().replace("Ё", "Е")
    alphabet = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
    return "".join(filter(lambda x: x in alphabet, text))


def vigenere_encrypt(plaintext, key):
    """Шифрование текста методом Виженера для русского алфавита"""
    plaintext = clean_text(plaintext)
    key = clean_text(key)
    if not key:
        return plaintext

    alphabet = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
    n = len(alphabet)
    char_to_index = {char: i for i, char in enumerate(alphabet)}

    ciphertext = []
    key_len = len(key)
    for i, char in enumerate(plaintext):
        p_idx = char_to_index[char]
        k_idx = char_to_index[key[i % key_len]]
        c_idx = (p_idx + k_idx) % n
        ciphertext.append(alphabet[c_idx])
    return "".join(ciphertext)


def vigenere_decrypt(ciphertext, key):
    """Дешифрование текста методом Виженера для русского алфавита"""
    ciphertext = clean_text(ciphertext)
    key = clean_text(key)
    if not key:
        return ciphertext

    alphabet = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
    n = len(alphabet)
    char_to_index = {char: i for i, char in enumerate(alphabet)}

    plaintext = []
    key_len = len(key)
    for i, char in enumerate(ciphertext):
        c_idx = char_to_index[char]
        k_idx = char_to_index[key[i % key_len]]
        p_idx = (c_idx - k_idx) % n
        plaintext.append(alphabet[p_idx])
    return "".join(plaintext)
