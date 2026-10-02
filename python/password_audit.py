#!/usr/bin/env python3
# ============================================================================
#  PassSafe — Password Strength Auditor (Python 3, stdlib only)
#  ---------------------------------------------------------------------------
#  Usage:
#     python3 password_audit.py --password "MyP@ssw0rd123"
#     python3 password_audit.py --interactive
#     python3 password_audit.py --file rockyou_sample.txt --json out.json
#  Output: score /100, strength label, entropy, suggestions (console + JSON)
# ============================================================================

import argparse
import json
import math
import re
import sys

# Top ~150 most common passwords (RockYou-derived subset, educational use).
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567", "qwerty",
    "abc123", "111111", "123123", "admin", "letmein", "welcome", "monkey",
    "iloveyou", "dragon", "password1", "sunshine", "princess", "football",
    "baseball", "superman", "batman", "shadow", "master", "michael", "jennifer",
    "trustno1", "1234", "000000", "passw0rd", "password123", "qwerty123",
    "1q2w3e4r", "qwertyuiop", "asdfghjkl", "zxcvbnm", "zaq12wsx", "abc12345",
    "pokemon", "starwars", "hello", "freedom", "whatever", "ninja", "flower",
    "charlie", "donald", "jordan", "hunter2", "secret", "696969", "555555",
    "121212", "666666", "7777777", "88888888", "999999999", "987654321",
    "1234567890", "0123456789", "11111111", "qazwsx", "qwe123", "1qaz2wsx",
    "iloveu", "babygirl", "lovely", "forever", "summer", "winter", "spring",
    "autumn", "computer", "internet", "login", "admin123", "root", "toor",
    "changeme", "default", "pass", "test", "guest", "user", "server",
    "customer", "welcome1", "p@ssw0rd", "P@ssw0rd", "Password1",
    "bangladesh", "dhaka", "bangladdesh", "cricket", "tiger", "bob",
    "bangla", "bd2015", "123456789a", "a123456", "samsung", "apple",
    "google", "facebook", "instagram", "whatsapp", "youtube", "amazon",
}

SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiopasdfghjklzxcvbnm"]

STRENGTH_LABELS = [
    (0, "Very Weak"), (20, "Weak"), (40, "Fair"), (60, "Good"),
    (80, "Strong"), (95, "Excellent"),
]


def entropy_bits(password: str) -> float:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 33
    if pool == 0:
        return 0.0
    return len(password) * math.log2(pool)


def has_sequence(password: str) -> bool:
    pw = password.lower()
    for seq in SEQUENCES:
        for i in range(len(seq) - 3):
            if seq[i:i + 4] in pw or seq[i:i + 4][::-1] in pw:
                return True
    return False


def has_repeats(password: str) -> bool:
    return bool(re.search(r"(.)\1{2,}", password))


def has_year(password: str) -> bool:
    return bool(re.search(r"(19\d\d|20[0-2]\d)", password))


def analyze(password: str) -> dict:
    findings = []
    score = 100.0

    lower = password.lower()
    if lower in COMMON_PASSWORDS:
        findings.append("Password is in the top-known-breached passwords list")
        score -= 60
    if len(password) < 8:
        findings.append("Too short (minimum recommended: 12 characters)")
        score -= 25
    elif len(password) < 12:
        findings.append("Length below the 12+ character recommendation")
        score -= 10
    if len(password) >= 16:
        findings.append("Excellent length")
        score += 5
    if not re.search(r"[a-z]", password):
        findings.append("Add lowercase letters")
        score -= 8
    if not re.search(r"[A-Z]", password):
        findings.append("Add uppercase letters")
        score -= 8
    if not re.search(r"[0-9]", password):
        findings.append("Add digits")
        score -= 8
    if not re.search(r"[^a-zA-Z0-9]", password):
        findings.append("Add symbols (!@#$%…)")
        score -= 8
    if has_sequence(password):
        findings.append("Contains a common keyboard/character sequence")
        score -= 20
    if has_repeats(password):
        findings.append("Contains repeated characters")
        score -= 10
    if has_year(password):
        findings.append("Contains a year (very common in breaches)")
        score -= 8
    if lower in ("password", "qwerty", "admin", "letmein", "iloveyou"):
        score -= 40

    bits = entropy_bits(password)
    if bits < 28:
        findings.append(f"Very low entropy ({bits:.0f} bits) — brute-forceable instantly")
        score -= 20
    elif bits < 45:
        findings.append(f"Low entropy ({bits:.0f} bits)")
        score -= 10
    elif bits >= 70:
        findings.append(f"High entropy ({bits:.0f} bits)")

    score = max(0.0, min(100.0, score))
    label = next(
        lbl for threshold, lbl in reversed(STRENGTH_LABELS) if score >= threshold
    )

    suggestions = [
        "Use 14+ random characters (a passphrase of 4+ random words is best)",
        "Never reuse a password across sites — use a password manager",
        "Enable Two-Factor Authentication (TFA/2FA) everywhere",
        "Do not use names, birthdays, phone numbers or dictionary words",
    ]
    if score < 40:
        suggestions.insert(0, "🔴 Replace this password immediately — it would fall "
                               "in seconds with a common wordlist attack.")

    return {
        "password_length": len(password),
        "entropy_bits": round(bits, 1),
        "score": round(score),
        "strength": label,
        "findings": findings,
        "suggestions": suggestions,
    }


def main():
    ap = argparse.ArgumentParser(description="PassSafe — password strength auditor")
    ap.add_argument("--password", help="Password to analyze")
    ap.add_argument("--interactive", action="store_true", help="Prompt for password")
    ap.add_argument("--file", help="Analyze passwords from a file (one per line)")
    ap.add_argument("--json", default=None, help="Write results to a JSON file")
    args = ap.parse_args()

    pas = []
    if args.password:
        pas = [args.password]
    elif args.interactive:
        import getpass
        p = getpass.getpass("Enter password to analyze: ")
        pas = [p]
    elif args.file:
        with open(args.file, encoding="utf-8", errors="ignore") as f:
            pas = [line.strip() for line in f if line.strip()][:500]

    if not pas:
        print("Usage: python3 password_audit.py --password 'MyP@ssw0rd123'")
        sys.exit(1)

    results = []
    for p in pas:
        res = analyze(p)
        results.append({"password": p, **res})
        if len(pas) == 1:
            print("=" * 52)
            print(f"  PASS SAFE — Password Strength Report")
            print("=" * 52)
            print(f"  Strength : {res['strength']}  ({res['score']}/100)")
            print(f"  Length   : {res['password_length']} chars")
            print(f"  Entropy  : {res['entropy_bits']} bits")
            print("-" * 52)
            print("  Findings:")
            for f in res["findings"]:
                print(f"   • {f}")
            print("  Suggestions:")
            for s in res["suggestions"]:
                print(f"   • {s}")
            print("=" * 52)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"[✓] JSON saved to {args.json}")


if __name__ == "__main__":
    main()
