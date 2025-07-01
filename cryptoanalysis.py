from collections import Counter
import numpy as np

# Улучшенные частоты букв в русском языке (в процентах)
RUSSIAN_FREQ = {
    "О": 10.97,
    "Е": 8.45,
    "А": 8.01,
    "И": 7.35,
    "Н": 6.70,
    "Т": 6.26,
    "С": 5.47,
    "Р": 4.73,
    "В": 4.54,
    "Л": 4.40,
    "К": 3.49,
    "М": 3.21,
    "Д": 2.98,
    "П": 2.81,
    "У": 2.62,
    "Я": 2.01,
    "Ы": 1.90,
    "Ь": 1.74,
    "Г": 1.70,
    "З": 1.65,
    "Б": 1.59,
    "Ч": 1.44,
    "Й": 1.21,
    "Х": 0.97,
    "Ж": 0.94,
    "Ш": 0.73,
    "Ю": 0.64,
    "Ц": 0.48,
    "Щ": 0.36,
    "Э": 0.32,
    "Ф": 0.26,
    "Ъ": 0.04,
}


def kasiski_examination(ciphertext, max_key_length=20):
    """Определение длины ключа методом Касиски"""
    sequences = {}
    for length in range(3, 6):
        for i in range(len(ciphertext) - length):
            seq = ciphertext[i : i + length]
            if seq in sequences:
                sequences[seq].append(i)
            else:
                sequences[seq] = [i]

    # Фильтрация последовательностей
    repeats = {
        seq: positions for seq, positions in sequences.items() if len(positions) > 1
    }

    # Вычисление расстояний
    distances = []
    for positions in repeats.values():
        for i in range(len(positions)):
            for j in range(i + 1, len(positions)):
                distances.append(positions[j] - positions[i])

    # Нахождение НОД расстояний
    factors = Counter()
    for dist in distances:
        for i in range(2, min(dist, max_key_length) + 1):
            if dist % i == 0:
                factors[i] += 1

    # Возвращаем 3 наиболее вероятных длины
    if factors:
        return [length for length, _ in factors.most_common(3)]
    return [1]


def frequency_attack(ciphertext, key_length):
    """Улучшенный частотный анализ с проверкой нескольких кандидатов"""
    alphabet = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
    n = len(alphabet)
    char_to_index = {char: i for i, char in enumerate(alphabet)}
    key = []

    # Анализ каждого подблока
    for i in range(key_length):
        block = ciphertext[i::key_length]
        if len(block) == 0:
            key.append("А")
            continue

        best_candidates = []
        # Перебор всех возможных сдвигов
        for shift in range(n):
            decrypted = []
            for c in block:
                c_idx = char_to_index[c]
                p_idx = (c_idx - shift) % n
                decrypted.append(alphabet[p_idx])
            decrypted_str = "".join(decrypted)

            # Расчет частот
            freq = Counter(decrypted_str)
            total = len(decrypted_str)
            chi2 = 0
            for char, count in freq.items():
                observed = count / total * 100
                expected = RUSSIAN_FREQ.get(char, 0.01)
                chi2 += (observed - expected) ** 2 / expected

            best_candidates.append((shift, chi2))

        # Выбор лучших кандидатов (3 с наименьшим chi2)
        best_candidates.sort(key=lambda x: x[1])
        best_shift = best_candidates[0][0]
        key.append(alphabet[best_shift])

    return "".join(key)
