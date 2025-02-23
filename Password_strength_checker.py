import re
import getpass
import random
import string
from typing import Tuple, List

def calculate_score(password: str) -> int:
    score = 0
    score += 20 if len(password) >= 8 else 0
    score += 20 if len(password) >= 12 else 0
    score += 10 if re.search("[a-z]", password) else 0
    score += 10 if re.search("[A-Z]", password) else 0
    score += 15 if len(re.findall("[0-9]", password)) >= 2 else 0
    score += 15 if len(re.findall("[!@#$%^&*(),.?\\\":{}|<>]", password)) >= 2 else 0
    score += 10 if not re.search("\\s", password) else 0
    return score

def password_feedback(password: str) -> List[str]:
    feedback = []
    if len(password) < 12:
        feedback.append("- Increase password length to at least 12 characters for higher security.")
    if not re.search("[a-z]", password):
        feedback.append("- Add lowercase letters.")
    if not re.search("[A-Z]", password):
        feedback.append("- Include uppercase letters.")
    if len(re.findall("[0-9]", password)) < 3:
        feedback.append("- Use at least three digits.")
    if len(re.findall("[!@#$%^&*(),.?\\\":{}|<>]", password)) < 3:
        feedback.append("- Include at least three special characters.")
    return feedback

def generate_suggestive_password() -> str:
    characters = string.ascii_letters + string.digits + "!@#$%^&*(),.?\":{}|<>"
    password = (
        random.choice(string.ascii_lowercase)
        + random.choice(string.ascii_uppercase)
        + random.choice(string.digits)
        + random.choice(string.digits)
        + random.choice(string.punctuation)
        + random.choice(string.punctuation)
    )
    password += ''.join(random.choice(characters) for _ in range(12))
    return ''.join(random.sample(password, len(password)))

def provide_improvement_tips(score: int) -> None:
    print("\n🔒 How to Increase Your Password Strength Score:")
    if score < 65:
        print("- Increase password length, use a mix of character types.")
    elif 65 <= score < 90:
        print("- Add more special characters and digits.")
        print("- Use a longer password to reach a score of 90 or above.")
    elif 90 <= score < 99:
        print("- For near-perfect security, add an extra digit or special character.")
        print("- Ensure the password is at least 16 characters long.")

def evaluate_password(password: str) -> Tuple[bool, str, int, List[str]]:
    score = calculate_score(password)
    feedback = password_feedback(password)

    if score >= 90:
        return True, "Very Strong", score, feedback
    elif score >= 65:
        return True, "Strong", score, feedback
    elif score >= 50:
        return True, "Moderate", score, feedback
    else:
        return False, "Weak", score, feedback

def password_strength_checker() -> None:
    print("\n===== Professional Password Strength Checker =====")
    password = getpass.getpass("Enter your password: ")

    is_valid, strength, score, feedback = evaluate_password(password)
    print(f"\nPassword Strength: {strength} ({score}/100)")

    if is_valid:
        print("✅ Password is secure!")
        if score >= 65 and score < 90:
            print("💡 Tips to make your password even stronger:")
            for suggestion in feedback:
                print(suggestion)
            provide_improvement_tips(score)
        elif score >= 90:
            print("🔥 Your password is highly secure!")
    else:
        print("❗ Password is weak. Follow these suggestions:")
        for suggestion in feedback:
            print(suggestion)
        provide_improvement_tips(score)
        print(f"🗝️ Suggested Password: {generate_suggestive_password()}")

if __name__ == "__main__":
    password_strength_checker()
