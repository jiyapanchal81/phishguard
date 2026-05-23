from flask import Flask, render_template, request
import string
import sqlite3
from datetime import datetime
from ml_model import classify_message

app = Flask(__name__)


# ---------------- DATABASE ----------------

def init_db():
    """Create the incidents table if it does not already exist."""
    connection = sqlite3.connect("phishguard.db")
    connection.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_type TEXT NOT NULL,
            description TEXT NOT NULL,
            date_reported TEXT NOT NULL
        )
    """)
    connection.commit()
    connection.close()


def save_incident(incident_type, description):
    """Save one incident report into the database."""
    connection = sqlite3.connect("phishguard.db")
    date_reported = datetime.now().strftime("%d %B %Y, %H:%M")
    connection.execute(
        "INSERT INTO incidents (incident_type, description, date_reported) VALUES (?, ?, ?)",
        (incident_type, description, date_reported),
    )
    connection.commit()
    connection.close()


def get_incidents():
    """Fetch all incident reports from the database, newest first."""
    connection = sqlite3.connect("phishguard.db")
    connection.row_factory = sqlite3.Row
    rows = connection.execute(
        "SELECT id, incident_type, description, date_reported FROM incidents ORDER BY id DESC"
    ).fetchall()
    connection.close()
    return rows


init_db()


# ---------------- DATA ----------------

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "hunter2",
    "letmein", "welcome", "monkey", "dragon", "password1", "iloveyou",
    "admin", "login", "passw0rd", "1234567", "12345", "111111",
}

SUSPICIOUS_TLDS = (".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click")

PHISHING_KEYWORDS = (
    "login", "signin", "verify", "secure", "account",
    "update", "confirm", "banking", "password",
)

URGENCY_WORDS = ("urgent", "immediately", "act now", "as soon as possible",
                 "expire", "within 24 hours", "limited time", "right away")

THREAT_WORDS = ("suspended", "account closed", "locked", "terminated",
                "legal action", "deactivated", "unauthorised", "unauthorized")

SENSITIVE_WORDS = ("password", "pin number", "card number", "bank account",
                   "verify your account", "confirm your identity",
                   "login details", "security details")

GENERIC_GREETINGS = ("dear customer", "dear user", "dear sir", "dear madam",
                     "dear account holder", "valued customer")

MONEY_WORDS = ("you have won", "winner", "prize", "lottery",
               "claim your", "refund", "free gift", "cash reward")

CLICK_WORDS = ("click here", "click the link", "click below",
               "follow this link", "verify here", "update here")

QUIZ_QUESTIONS = [
    {
        "question": "What is \"phishing\"?",
        "options": [
            "A type of computer virus",
            "An attempt to trick you into giving away personal information",
            "A way to make your internet faster",
            "A type of firewall",
        ],
        "correct": 1,
    },
    {
        "question": "An email says \"Your account will be closed in 24 hours unless you verify now.\" What is this most likely?",
        "options": [
            "A genuine urgent message you should act on immediately",
            "A phishing attempt using urgency to pressure you",
            "A normal account notification",
            "A software update",
        ],
        "correct": 1,
    },
    {
        "question": "Which of these web addresses looks most suspicious?",
        "options": [
            "https://www.paypal.com",
            "http://paypa1-login-secure.tk",
            "https://www.amazon.co.uk",
            "https://www.gov.uk",
        ],
        "correct": 1,
    },
    {
        "question": "You're unsure whether an email from your \"bank\" is genuine. What should you do?",
        "options": [
            "Click the link in the email to check",
            "Reply to the email asking if it's real",
            "Contact the bank directly using a number or website you already trust",
            "Forward it to all your friends",
        ],
        "correct": 2,
    },
    {
        "question": "What makes a password strong?",
        "options": [
            "Using your name and date of birth",
            "A short word that's easy to remember",
            "A long mix of upper/lowercase letters, numbers and symbols",
            "Using \"password123\"",
        ],
        "correct": 2,
    },
]


# ---------------- LOGIC ----------------

def analyze_password(password):
    """Check a password against six rules. Returns a result dictionary."""
    checks = []

    length = len(password)
    if length >= 12:
        checks.append({"passed": True, "message": f"Good length ({length} characters)"})
    elif length >= 8:
        checks.append({"passed": False, "message": f"Acceptable length ({length}) — aim for 12 or more"})
    else:
        checks.append({"passed": False, "message": f"Too short ({length} characters) — minimum 8"})

    if any(c.isupper() for c in password):
        checks.append({"passed": True, "message": "Contains uppercase letters"})
    else:
        checks.append({"passed": False, "message": "No uppercase letters"})

    if any(c.islower() for c in password):
        checks.append({"passed": True, "message": "Contains lowercase letters"})
    else:
        checks.append({"passed": False, "message": "No lowercase letters"})

    if any(c.isdigit() for c in password):
        checks.append({"passed": True, "message": "Contains numbers"})
    else:
        checks.append({"passed": False, "message": "No numbers"})

    if any(c in string.punctuation for c in password):
        checks.append({"passed": True, "message": "Contains special characters"})
    else:
        checks.append({"passed": False, "message": "No special characters"})

    if password.lower() in COMMON_PASSWORDS:
        checks.append({"passed": False, "message": "Found on common-password lists"})
    else:
        checks.append({"passed": True, "message": "Not on common-password lists"})

    score = 0
    for check in checks:
        if check["passed"]:
            score += 1

    if score <= 2:
        rating = "Very Weak"
    elif score == 3:
        rating = "Weak"
    elif score == 4:
        rating = "Moderate"
    elif score == 5:
        rating = "Strong"
    else:
        rating = "Very Strong"

    return {"score": score, "rating": rating, "checks": checks}


def analyze_url(url):
    """Check a URL for rule-based phishing red flags. Returns a result dictionary."""
    url = url.strip()
    url_lower = url.lower()
    flags = []

    if not url_lower.startswith("https://"):
        flags.append("Does not use HTTPS (a secure connection)")

    after_scheme = url_lower.split("://")[-1]
    domain = after_scheme.split("/")[0]

    if domain != "" and all(c.isdigit() or c == "." for c in domain):
        flags.append("Uses an IP address instead of a domain name")

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        flags.append("Uses a suspicious domain ending (e.g. .tk, .xyz)")

    if "@" in url:
        flags.append("Contains an '@' symbol, which can disguise the real site")

    if domain.count(".") >= 4:
        flags.append("Has an unusually large number of subdomains")

    found = [word for word in PHISHING_KEYWORDS if word in url_lower]
    if found:
        flags.append("Contains phishing-bait words: " + ", ".join(found))

    count = len(flags)
    if count == 0:
        rating, level = "Looks safe", "success"
    elif count <= 2:
        rating, level = "Suspicious — be careful", "warning"
    else:
        rating, level = "High risk — likely phishing", "danger"

    return {"rating": rating, "level": level, "count": count, "flags": flags}


def analyze_message(message):
    """Check an email or text message for rule-based phishing red flags."""
    text = message.lower()
    flags = []

    if any(word in text for word in URGENCY_WORDS):
        flags.append("Uses urgency or pressure ('urgent', 'act now', etc.)")

    if any(word in text for word in THREAT_WORDS):
        flags.append("Contains a threat ('account suspended', 'locked', etc.)")

    if any(word in text for word in SENSITIVE_WORDS):
        flags.append("Asks for sensitive information (password, card details, etc.)")

    if any(word in text for word in GENERIC_GREETINGS):
        flags.append("Uses a generic greeting ('Dear Customer') instead of your name")

    if any(word in text for word in MONEY_WORDS):
        flags.append("Mentions money, prizes or winnings to bait you")

    if any(word in text for word in CLICK_WORDS):
        flags.append("Pressures you to click a link")

    count = len(flags)
    if count == 0:
        rating, level = "Looks safe", "success"
    elif count <= 2:
        rating, level = "Suspicious — be careful", "warning"
    else:
        rating, level = "High risk — likely phishing", "danger"

    return {"rating": rating, "level": level, "count": count, "flags": flags}


# ---------------- ROUTES ----------------

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/password", methods=["GET", "POST"])
def password_checker():
    result = None
    if request.method == "POST":
        password = request.form.get("password", "")
        if password:
            result = analyze_password(password)
    return render_template("password.html", result=result)


@app.route("/url", methods=["GET", "POST"])
def url_checker():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "")
        if url:
            result = analyze_url(url)
    return render_template("url.html", result=result)


@app.route("/message", methods=["GET", "POST"])
def message_checker():
    result = None
    if request.method == "POST":
        message = request.form.get("message", "")
        if message:
            result = analyze_message(message)
    return render_template("message.html", result=result)


@app.route("/quiz", methods=["GET", "POST"])
def quiz():
    result = None
    if request.method == "POST":
        score = 0
        feedback = []
        number = 0
        for question in QUIZ_QUESTIONS:
            chosen = request.form.get("q" + str(number))
            correct = str(question["correct"])
            is_correct = (chosen == correct)
            if is_correct:
                score += 1
            feedback.append({
                "question": question["question"],
                "is_correct": is_correct,
                "correct_answer": question["options"][question["correct"]],
            })
            number += 1
        result = {"score": score, "total": len(QUIZ_QUESTIONS), "feedback": feedback}
    return render_template("quiz.html", questions=QUIZ_QUESTIONS, result=result)


@app.route("/report", methods=["GET", "POST"])
def report_incident():
    saved = False
    if request.method == "POST":
        incident_type = request.form.get("incident_type", "")
        description = request.form.get("description", "")
        if incident_type and description:
            save_incident(incident_type, description)
            saved = True
    return render_template("report.html", saved=saved)


@app.route("/incidents")
def view_incidents():
    incidents = get_incidents()
    return render_template("incidents.html", incidents=incidents)


@app.route("/ml-demo", methods=["GET", "POST"])
def ml_demo():
    rule_result = None
    ml_result = None
    if request.method == "POST":
        message = request.form.get("message", "")
        if message:
            rule_result = analyze_message(message)
            ml_result = classify_message(message)
    return render_template("ml_demo.html", rule_result=rule_result, ml_result=ml_result)


if __name__ == "__main__":
    app.run(debug=True, port=5001)