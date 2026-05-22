# test_password.py
# Step 2b — All six password rules, written in pure Python.
# Run from Terminal:  python3 test_password.py

import string


# A small list of common passwords. A real product would use a much bigger list.
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "hunter2",
    "letmein", "welcome", "monkey", "dragon", "password1", "iloveyou",
    "admin", "login", "passw0rd", "1234567", "12345", "111111",
}

# Ask the user to type a password
password = input("Enter a password to check: ")

# Count how many rules pass
score = 0

print("")  # blank line for spacing

# Rule 1 — Length
length = len(password)
if length >= 12:
    print(f"PASS — Good length ({length} characters)")
    score += 1
elif length >= 8:
    print(f"FAIL — Acceptable length ({length}) but aim for 12 or more")
else:
    print(f"FAIL — Too short ({length} characters) — minimum 8")

# Rule 2 — Uppercase letters
if any(c.isupper() for c in password):
    print("PASS — Contains uppercase letters")
    score += 1
else:
    print("FAIL — No uppercase letters")

# Rule 3 — Lowercase letters
if any(c.islower() for c in password):
    print("PASS — Contains lowercase letters")
    score += 1
else:
    print("FAIL — No lowercase letters")

# Rule 4 — Numbers
if any(c.isdigit() for c in password):
    print("PASS — Contains numbers")
    score += 1
else:
    print("FAIL — No numbers")

# Rule 5 — Special characters
if any(c in string.punctuation for c in password):
    print("PASS — Contains special characters")
    score += 1
else:
    print("FAIL — No special characters")

# Rule 6 — Not on the common-password list
if password.lower() in COMMON_PASSWORDS:
    print("FAIL — Found on common-password lists")
else:
    print("PASS — Not on common-password lists")
    score += 1

# Translate the score into a rating
print("")
print(f"Score: {score} out of 6")

if score <= 2:
    print("Rating: VERY WEAK")
elif score == 3:
    print("Rating: WEAK")
elif score == 4:
    print("Rating: MODERATE")
elif score == 5:
    print("Rating: STRONG")
else:
    print("Rating: VERY STRONG")