# 🛡️ PhishGuard

**A rule-based phishing detection and security awareness web application.**

PhishGuard is a small web app that helps everyday users make safer decisions
online. It checks passwords and links, flags suspicious messages, tests the
user's knowledge with a quiz, and keeps a log of reported phishing incidents.

This project was built for the Professional Development module (S2-PFD200)
as part of an FdSc Computing course.

## Features

- **Password Strength Checker** — rates a password against six rules (length, character variety, common-password lists).
- **Security Awareness Quiz** — a five-question multiple-choice quiz with instant feedback.
- **URL Phishing Checker** — inspects a web address for six common phishing red flags.
- **Suspicious Message Checker** — scans an email or text message for phishing warning signs.
- **Incident Report Log** — lets users report phishing incidents, saved to a database and viewable as a log.

## Tech stack

- **Python 3** with the **Flask** web framework
- **HTML & CSS** for the interface (templates rendered with Jinja2)
- **SQLite** for storing incident reports

All detection is **rule-based** — the app uses defined checks and keyword
lists rather than machine learning. This was a deliberate choice to keep the
logic transparent and within scope. See *Future Work* below.

## How to run it locally

1. Clone or download this repository.
2. Open a terminal in the project folder.
3. Create and activate a virtual environment (`python3 -m venv venv` then `source venv/bin/activate`).
4. Install the requirements with `pip install -r requirements.txt`.
5. Start the app with `python3 app.py`.
6. Open http://127.0.0.1:5001 in a browser.

The SQLite database (`phishguard.db`) is created automatically the first time
the app runs.

## Project structure

The project contains `app.py` (Flask routes, detection logic and database
functions), a `static` folder for the CSS, and a `templates` folder holding
the homepage and one page per feature.

## Future work

The detection currently relies on fixed rules and keyword lists. A natural
next step would be to train a **machine learning model** on labelled phishing
data to recognise patterns that fixed rules miss. Other possible improvements
include user accounts, deploying the app to a public host, and expanding the
rule and keyword sets.

## Author

Student project for Professional Development (S2-PFD200).