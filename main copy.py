import vigenere
import cryptoanalysis
import os
import time
import numpy as np
import matplotlib.pyplot as plt
from collections import Counter
import math


# Функция для вычисления энтропии ключа
def calculate_entropy(key):
    counter = Counter(key)
    total = len(key)
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


# Функция для определения типа распределения ключа
def detect_key_distribution(key):
    if len(key) == 0:
        return "unknown"

    # Проверка на равномерное распределение
    counter = Counter(key)
    max_count = max(counter.values())
    if max_count / len(key) < 0.15:  # Пороговое значение
        return "uniform"

    # Другие проверки можно добавить здесь
    return "other"


# Функция для сравнения ключей
def compare_keys(original, found):
    if len(original) != len(found):
        return 0.0

    matches = sum(1 for o, f in zip(original, found) if o == f)
    return matches / len(original) * 100


def main():
    INPUT_FILE = "input.txt"
    OUTPUT_FILE = "results.txt"
    KEYS_FILE = "keys.txt"  # Файл с дополнительными ключами
    DEFAULT_KEYS = [
        "АААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААААА",
        "МИР",
        "ЩФЛЗАРСХГЮВКМЕЙЦЖЮБТЪЁЧЫПИЖНУЭЙДЯФЪЖЧТЬБХЦЩСШЫМЖЮЩДЪГШЭНПЕВХЧЩЫГТЯЦЙЖЩЮЭЛЬБЕФВЁХЪЧДЛИЫКР",
        "СЕКРЕТСЕКРЕТСЕКРЕТСЕКРЕТСЕКРЕТСЕКРЕТБЮШГЭТЛЦЖШЧМЙЗЦЭЪЪПЬЁШТЩЫЧЛЮДВЦЖШГФЬ",
        "МНПОМНОППМНООММНПППНПОННММОППМНННОММППМНННОПНПОМНОННМНОПМННПОМНОММПОММННПОМНОНМППМНПНПОНПННОПМ",
        "МЛПМЛОМПЛНЛПЛМЛПЛПЛМПЛНПМЛПЛНЛПМПЛПЛМПНПЛЛМППМЛПЛЛПЛНПМПЛПМЛПЛПЛЛПЛПЛПЛПМЛНЛПЛПЛППМПЛНЛПЛПМЛ",
        "БВГБАГАВДАБГГВВЕБГАБВВЕАГГБГГАЕАВГБДГВААГДЕБГААГГБЕАГГГАЕАБАААГААГБЕАГГЕБГАБГЕБАБАГААГГАЕБВААГ",
        "АЯБЮАГЩАШВЯАГЯЩАГШЮЯАЩАГЯЮАБШАГЮШЯАГЩАЯАГЮШЩАБАГЯЮАГЩАГШЯЮАГЯБАЩЮАШЯАГЩАГЮАБЩАГШЯАГЮАЩЮАГА",
        "ЦКЯФЭТЗНЙЩХБЮЕМХСЁЛДРПЮЫЪГШТЬВАЖЖШЧПСЦЖЯФЦИМЭЩЙГЖХШДЯЮОПЦЫЁГЗРЧЙЩЫЪВЖЭТЦЁСХПЮЯОКМЕФЧЛДНУЬЩЦ",
        "РСПЙООКУЖР",
        "ОФМНРУТСНО",
        "ЕГЖВЖЕБЕДВ",
        "ЦЧЩСЪЯКЫЩО",
    ]  # Ключи по умолчанию
    """
    1. Минимальная энтропия
    2. Минимальный размер
    3. Максимальная энтропия
    4. Средняя энтропия
    5. Нормальное распределение
    6. Биномиальное распределение
    7. Пауссоновское распределение
    8. Сигма-распределение
    9. Равномерное распределение
    ---### Ключи по 10 символов ##---
    10.Нормальное распределение
    11.Биномиальное распределение
    12.Пауссоновское распределение
    13. Сигма распределение
    """
    if not os.path.exists(INPUT_FILE):
        print(f"Ошибка: файл {INPUT_FILE} не найден!")
        return

    # Сбор всех ключей (по умолчанию + из файла)
    all_keys = DEFAULT_KEYS.copy()

    key_characteristics = []
    for key in unique_keys:
        key_characteristics.append(
            {
                "key": key,
                "length": len(key),
                "entropy": calculate_entropy(key),
                "distribution": detect_key_distribution(key),
            }
        )

    if os.path.exists(KEYS_FILE):
        try:
            with open(KEYS_FILE, "r", encoding="utf-8") as f_keys:
                file_keys = [line.strip() for line in f_keys]
                file_keys = [k for k in file_keys if k]  # Фильтрация пустых ключей
                print(f"Найдено {len(file_keys)} ключей в файле {KEYS_FILE}")
                all_keys.extend(file_keys)
        except Exception as e:
            print(f"Ошибка при чтении {KEYS_FILE}: {e}")
    else:
        print(f"Файл {KEYS_FILE} не найден, используются только ключи по умолчанию")

    # Удаление дубликатов с сохранением порядка
    unique_keys = []
    seen = set()
    for key in all_keys:
        if key not in seen:
            seen.add(key)
            unique_keys.append(key)

    print(f"Всего уникальных ключей для теста: {len(unique_keys)}")

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        plaintext = f.read()

    results = []

    for key in unique_keys:
        # ... (остальной код без изменений)
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
            f.write(f"Шифртекст (начало): {res['ciphertext']}\n")
            f.write(
                f"Расшифровано найденным ключом (начало): {res['decrypted_with_found']}\n"
            )
            f.write("-" * 80 + "\n")

    print(f"Результаты сохранены в {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
