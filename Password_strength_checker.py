# password_strength_checker.py

import re
import getpass
import random
import string
import hashlib # For SHA-1 hashing for HIBP check
import requests # For making HTTP requests to HIBP API
from typing import Tuple, List, Optional # Optional for breach count

# --- HIBP Constants ---
HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
# We use a timeout for the API request
HIBP_REQUEST_TIMEOUT = 5 # seconds

def calculate_score(password: str) -> int:
    score = 0
    # Check length first as it's fundamental
    length = len(password)
    score += 20 if length >= 8 else 0
    score += 20 if length >= 12 else 0
    score += 10 if re.search("[a-z]", password) else 0
    score += 10 if re.search("[A-Z]", password) else 0
    # Use more robust digit/special char checks
    digit_count = len(re.findall("[0-9]", password))
    special_char_count = len(re.findall("[!@#$%^&*(),.?\\\":{}|<>]", password))
    score += 15 if digit_count >= 2 else 0
    score += 15 if special_char_count >= 2 else 0
    score += 10 if not re.search("\\s", password) else 0 # No spaces

    # Deductions for simple patterns (optional, but good practice)
    # Example: simple sequential numbers or letters (can make score calculation complex, keeping simple for now)
    # score -= 10 if re.search(r'123|abc|qwe', password, re.IGNORECASE) else 0 # Basic pattern check

    return score

def password_feedback(password: str) -> List[str]:
    feedback = []
    length = len(password)
    digit_count = len(re.findall("[0-9]", password))
    special_char_count = len(re.findall("[!@#$%^&*(),.?\\\":{}|<>]", password))

    if length < 8:
         feedback.append("- Password is too short. Aim for at least 12 characters.")
    elif length < 12:
        feedback.append("- Increase password length for higher security (aim for 12+).")
    if not re.search("[a-z]", password):
        feedback.append("- Add lowercase letters.")
    if not re.search("[A-Z]", password):
        feedback.append("- Include uppercase letters.")
    # Suggest slightly more specific counts than score calculation requires
    if digit_count < 3: # Suggest at least 3 digits
        feedback.append(f"- Use at least three digits (currently {digit_count}).")
    if special_char_count < 3: # Suggest at least 3 special characters
        feedback.append(f"- Include at least three special characters (currently {special_char_count}).")
    if re.search("\\s", password):
         feedback.append("- Avoid using spaces.")
    # Add feedback based on score ranges for more tailored tips?
    # This is already somewhat covered by provide_improvement_tips, maybe keep feedback simple list of missing elements
    return feedback

def generate_suggestive_password() -> str:
    # Adjusted generation to prioritize mix and length
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special_chars = "!@#$%^&*(),.?\":{}|<>[]" # Added square brackets

    # Ensure at least one of each required type
    password_chars = [
        random.choice(lowercase),
        random.choice(uppercase),
        random.choice(digits),
        random.choice(digits), # At least two digits
        random.choice(special_chars),
        random.choice(special_chars) # At least two special chars
    ]

    # Fill the rest up to a good length (e.g., 14-16 characters total)
    all_chars = lowercase + uppercase + digits + special_chars
    remaining_length = random.randint(8, 10) # For a total length of 6 + 8-10 = 14-16
    password_chars.extend(random.choice(all_chars) for _ in range(remaining_length))

    # Shuffle to make it random
    random.shuffle(password_chars)

    return ''.join(password_chars)


def provide_improvement_tips(score: int, breach_count: int) -> List[str]: # Added breach_count
    tips = []
    # --- Prioritize Breach Warning ---
    if breach_count > 0:
        tips.append(f"🚨 **SEVERE WARNING:** This password was found {breach_count} times in public data breaches. **You must not use this password anywhere.** Even a high strength score is irrelevant if the password is known to attackers.")
    else:
        # --- Score-based tips (only if not breached) ---
        tips.append("\n🔒 How to Increase Your Password Strength Score:")
        if score < 50: # Weak
             tips.append("- Your password is weak. It's highly recommended to choose a completely different password. Use a password manager.")
        elif score < 65: # Moderate
            tips.append("- Your password strength is Moderate. It offers some protection, but could be easily guessed or cracked with more effort.")
            tips.append("- To reach Strong or Very Strong, significantly increase length and add more character types (uppercase, lowercase, digits, special characters).")
        elif 65 <= score < 90: # Strong
            tips.append("- Your password strength is Strong. This is good, but consider making it Very Strong for better resilience against future attacks.")
            tips.append("- Add more special characters or digits.")
            tips.append("- Aim for a length of at least 16 characters.")
        elif 90 <= score < 99: # Very Strong (almost perfect)
            tips.append("- Your password strength is Very Strong. Excellent!")
            tips.append("- For theoretical maximum security, ensure it's at least 16 characters and contains a diverse mix.")
        elif score == 100: # Perfect score (based on current calculation)
             tips.append("🔥 Your password is Very Strong and achieved the maximum score based on criteria. Excellent!")

    # --- General Best Practices (always include) ---
    tips.append("\n🛡️ General Password Security Best Practices:")
    tips.append("- **Use a unique password for every account.** Never reuse passwords.")
    tips.append("- **Consider using a reputable password manager** (like Bitwarden, LastPass, 1Password) to generate and store strong, unique passwords.")
    tips.append("- **Enable Two-Factor Authentication (2FA/MFA)** whenever possible for an extra layer of security.")


    return tips


def check_hibp(password: str) -> int:
    """
    Checks if a password has been found in public data breaches using the HIBP API.
    Uses a privacy-preserving method (k-Anonymity).

    Args:
        password: The plain text password string.

    Returns:
        The number of times the password was found in breaches, or -1 if API check failed.
    """
    if not password:
        return 0 # An empty password isn't 'pwned' in the database sense

    # Calculate SHA-1 hash of the password (case-insensitive is common for HIBP check)
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]

    url = f"{HIBP_API_URL}{prefix}"

    try:
        # Make the request to the HIBP API
        response = requests.get(url, timeout=HIBP_REQUEST_TIMEOUT)

        # HIBP API uses status codes: 200 means found, 404 means not found, others are errors
        if response.status_code == 404:
            return 0 # Not found in the database for this prefix

        response.raise_for_status() # Raise an exception for bad status codes (4xx or 5xx)

        # Parse the response body (each line is Suffix:Count)
        lines = response.text.splitlines()
        for line in lines:
            parts = line.split(':')
            # Ensure line format is correct and case matches
            if len(parts) == 2 and parts[0] == suffix:
                try:
                    return int(parts[1]) # Return the count
                except ValueError:
                    print(f"Warning: HIBP API returned invalid count format: {line}")
                    return 0 # Treat as not found if count is garbage

        # If the loop finishes, the suffix was not found for the given prefix
        return 0

    except requests.exceptions.RequestException as e:
        print(f"Error querying HIBP API: {e}")
        # Return a special value indicating the check failed
        return -1
    except Exception as e:
         print(f"An unexpected error occurred during HIBP check: {e}")
         return -1 # Handle other potential errors


# Modified evaluate_password to include HIBP check
def evaluate_password(password: str) -> Tuple[bool, str, int, List[str], int]: # Added int for breach_count
    """
    Evaluates password strength, provides feedback, and checks against HIBP breaches.

    Returns:
        Tuple: (is_secure, strength_level, score, feedback_list, breach_count)
        is_secure: bool (based on score, can add breach check here)
        strength_level: str
        score: int
        feedback_list: List[str] (suggestions for improvement)
        breach_count: int (number of times found in breaches, -1 if check failed)
    """
    score = calculate_score(password)
    feedback = password_feedback(password)

    # --- Perform HIBP Check ---
    breach_count = check_hibp(password)
    # ==========================

    # Determine strength level based on score
    if score >= 90:
        strength = "Very Strong"
        is_valid = True
    elif score >= 65:
        strength = "Strong"
        is_valid = True
    elif score >= 50:
        strength = "Moderate"
        is_valid = True
    else:
        strength = "Weak"
        is_valid = False

    # IMPORTANT: If found in breaches, it is NEVER SECURE, regardless of score
    # We can optionally override is_valid here for the "Is it secure?" check
    # For this demo, let's return the score-based validity but include the breach count
    # so the UI can show a strong warning even for a "Very Strong" score if breached.

    return is_valid, strength, score, feedback, breach_count

# Removed the direct command-line interface part (__main__)
# as the Flask app will handle interaction.
# if __name__ == "__main__":
#     password_strength_checker()