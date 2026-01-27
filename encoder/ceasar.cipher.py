def caesar_cipher(text, shift):
    """Verschlüsselt Text mit Caesar-Cipher und gegebener Verschiebung"""
    alphabet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
    result = ""
    for buchstabe in text:
        if buchstabe in alphabet:
            neue_position = (alphabet.index(buchstabe) + shift) % len(alphabet)
            result += alphabet[neue_position]
        else:
            result += buchstabe
    return result

def alle_verschiebungen(text):
    """Gibt alle 26 möglichen Caesar-Cipher Varianten aus"""
    for shift in range(26):
        result = caesar_cipher(text, shift)
        print(f"Shift {shift:2d}: {result}")



if __name__ == "__main__":
    print("=" * 29)
    print("Caesar-Cipher Entschlüsseler")
    print("=" * 29)
    text = input("Text eingeben: ").lower()
    print()
    alle_verschiebungen(text)
