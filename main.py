import vigenere
import cryptoanalysis
import os
import time


def main():
    INPUT_FILE = "input.txt"
    OUTPUT_FILE = "results.txt"
    KEYS = ["АОАОА", "МИР", "КЛЮЧ", "СЕКРЕТ", "АНАЛИЗ"]

    if not os.path.exists(INPUT_FILE):
        print(f"Ошибка: файл {INPUT_FILE} не найден!")
        return

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        plaintext = f.read()

    results = []

    for key in KEYS:
        # Шифрование
        start_time = time.time()
        ciphertext = vigenere.vigenere_encrypt(plaintext, key)
        encrypt_time = time.time() - start_time

        # Криптоанализ
        start_time = time.time()

        # Пробуем несколько длин ключа
        key_length_candidates = cryptoanalysis.kasiski_examination(ciphertext)
        best_accuracy = 0
        best_found_key = ""
        best_key_length = 0
        best_decrypted = ""

        for k_len in key_length_candidates:
            found_key = cryptoanalysis.frequency_attack(ciphertext, k_len)
            decrypted = vigenere.vigenere_decrypt(ciphertext, found_key)

            # Оценка точности
            clean_plain = vigenere.clean_text(plaintext)
            clean_decrypted = vigenere.clean_text(decrypted)
            min_len = min(len(clean_plain), len(clean_decrypted))
            accuracy = (
                sum(1 for i in range(min_len) if clean_plain[i] == clean_decrypted[i])
                / len(clean_plain)
                * 100
            )

            if accuracy > best_accuracy:
                best_accuracy = accuracy
                best_found_key = found_key
                best_key_length = k_len
                best_decrypted = decrypted

        decrypt_time = time.time() - start_time

        # Дешифрование исходным ключом
        correct_decrypted = vigenere.vigenere_decrypt(ciphertext, key)
        clean_correct = vigenere.clean_text(correct_decrypted)
        clean_original = vigenere.clean_text(plaintext)
        correct_accuracy = (
            sum(
                1
                for i in range(min(len(clean_original), len(clean_correct)))
                if clean_original[i] == clean_correct[i]
            )
            / len(clean_original)
            * 100
        )

        results.append(
            {
                "original_key": key,
                "found_key": best_found_key,
                "key_length": best_key_length,
                "encrypt_time": encrypt_time,
                "decrypt_time": decrypt_time,
                "accuracy": best_accuracy,
                "correct_decrypt_accuracy": correct_accuracy,
                "ciphertext": (
                    ciphertext[:100] + "..." if len(ciphertext) > 100 else ciphertext
                ),
                "decrypted_with_found": (
                    best_decrypted[:100] + "..." if best_decrypted else ""
                ),
                "decrypted_with_original": (
                    correct_decrypted[:100] + "..." if correct_decrypted else ""
                ),
            }
        )

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for i, res in enumerate(results):
            f.write(f"Тест #{i+1}\n")
            f.write(f"Исходный ключ: {res['original_key']}\n")
            f.write(f"Найденный ключ: {res['found_key']}\n")
            f.write(f"Длина ключа: {res['key_length']}\n")
            f.write(f"Время шифрования: {res['encrypt_time']:.6f} сек\n")
            f.write(f"Время анализа: {res['decrypt_time']:.6f} сек\n")
            f.write(f"Точность криптоанализа: {res['accuracy']:.2f}%\n")
            f.write(
                f"Точность дешифрования исходным ключом: {res['correct_decrypt_accuracy']:.2f}%\n"
            )
            f.write(f"Шифртекст (начало): {res['ciphertext']}\n")
            f.write(
                f"Расшифровано найденным ключом (начало): {res['decrypted_with_found']}\n"
            )
            f.write(
                f"Расшифровано исходным ключом (начало): {res['decrypted_with_original']}\n"
            )
            f.write("-" * 80 + "\n")

    print(f"Результаты сохранены в {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
