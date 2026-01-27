import string

ALPHABET = string.ascii_lowercase
EN_FREQ = [0.082, 0.015, 0.028, 0.043, 0.13, 0.022, 0.02, 0.061, 0.07, 0.002, 0.008, 0.04, 0.024, 0.067, 0.075, 0.019, 0.001, 0.06, 0.063, 0.091, 0.028, 0.01, 0.024, 0.002, 0.02, 0.001]


def _shift_char(ch: str, key_shift: int) -> str:
    """Shiftet einen Buchstaben um key_shift (kann negativ sein)."""
    is_upper = ch.isupper()
    base = ALPHABET
    ch_low = ch.lower()
    if ch_low not in base:
        return ch
    idx = base.index(ch_low)
    new_ch = base[(idx + key_shift) % len(base)]
    return new_ch.upper() if is_upper else new_ch


def _chi_squared(counts, total):
    """Chi-Quadrat gegen englische Frequenzen."""
    if total == 0:
        return float("inf")
    score = 0.0
    for i, c in enumerate(counts):
        expected = EN_FREQ[i] * total
        if expected > 0:
            score += (c - expected) ** 2 / expected
    return score


def _ioc(text_slice: str) -> float:
    """Index of coincidence fuer einen Text-Teilstrom."""
    counts = [0] * len(ALPHABET)
    for ch in text_slice:
        if ch in ALPHABET:
            counts[ALPHABET.index(ch)] += 1
    n = sum(counts)
    if n <= 1:
        return 0.0
    num = sum(c * (c - 1) for c in counts)
    denom = n * (n - 1)
    return num / denom if denom else 0.0


def guess_key_length(cipher_only: str, max_len: int = 12) -> int:
    """Schaetzt die Schluessellaenge per IOC (1..max_len)."""
    best_len = 1
    best_ioc = 0.0
    for L in range(1, max_len + 1):
        slices = [cipher_only[i::L] for i in range(L)]
        avg_ioc = sum(_ioc(s) for s in slices) / L
        if avg_ioc > best_ioc:
            best_ioc = avg_ioc
            best_len = L
    return best_len


def guess_key(cipher_only: str, max_len: int = 12) -> str:
    """Leitet einen Schluessel aus dem Ciphertext ab (nur Buchstaben)."""
    cipher_only = ''.join(ch for ch in cipher_only.lower() if ch in ALPHABET)
    if not cipher_only:
        raise ValueError("Kein verwertbarer Ciphertext zum Raten")

    key_len = guess_key_length(cipher_only, max_len=max_len)
    guessed = []
    for offset in range(key_len):
        slice_text = cipher_only[offset::key_len]
        counts = [0] * len(ALPHABET)
        for ch in slice_text:
            counts[ALPHABET.index(ch)] += 1

        best_shift = 0
        best_score = float("inf")
        for shift in range(len(ALPHABET)):
            shifted_counts = counts[shift:] + counts[:shift]
            score = _chi_squared(shifted_counts, len(slice_text))
            if score < best_score:
                best_score = score
                best_shift = shift
        guessed.append(ALPHABET[best_shift])
    return ''.join(guessed)


def vigenere(text: str, key: str, decrypt: bool = True) -> str:
    """Vigenere ver- oder entschluesseln.

    decrypt=True  -> entschluesseln
    decrypt=False -> verschluesseln
    """
    if not key:
        raise ValueError("Key darf nicht leer sein")

    # Nur Buchstaben zulassen, Rest ignorieren
    key = ''.join(k.lower() for k in key if k.isalpha())
    if not key:
        raise ValueError("Key muss Buchstaben enthalten (a-z)")

    result_chars = []
    key_len = len(key)
    ki = 0

    for ch in text:
        if ch.lower() in ALPHABET:
            k_shift = ALPHABET.index(key[ki % key_len])
            if decrypt:
                k_shift = -k_shift
            result_chars.append(_shift_char(ch, k_shift))
            ki += 1
        else:
            result_chars.append(ch)

    return ''.join(result_chars)


def main():
    print("=" * 40)
    print("Vigenere-Cipher Entschluesseler")
    print("=" * 40)
    modus = input("[E]ntschluesseln oder [V]erschluesseln? (E/V): ").strip().lower() or "e"
    decrypt = modus != "v"

    text = input("Text eingeben: ")
    key = input("Schluessel eingeben (leer lassen zum Raten): ")

    try:
        cleaned_key = ''.join(k.lower() for k in key if k.isalpha())

        if decrypt and not cleaned_key:
            guessed = guess_key(text)
            cleaned_key = guessed
            print(f"Geratener Key: {guessed}")

        output = vigenere(text, cleaned_key, decrypt=decrypt)
    except ValueError as exc:
        print(f"Fehler: {exc}")
        return

    print("\nVerwendeter Key:", cleaned_key)
    print("Modus:", "Entschluesseln" if decrypt else "Verschluesseln")
    print("Ergebnis:")
    print(output)


if __name__ == "__main__":
    main()