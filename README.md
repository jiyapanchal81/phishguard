# 🛡️ PhishGuard

**A rule-based phishing detection and security awareness web application.**

PhishGuard is a small web app that helps everyday users make safer decisions online. It checks passwords and links, flags suspicious messages, tests the user's knowledge with a quiz, keeps a log of reported phishing incidents, and includes a small machine-learning demo that classifies messages.

This project was built for the Professional Development module (S2-PFD200) as part of an FdSc Computing course.

## Features

- **Password Strength Checker** — rates a password against six rules (length, character variety, common-password lists).
- **URL Phishing Checker** — inspects a web address for six common phishing red flags (missing HTTPS, IP addresses, suspicious domain endings, the "@" symbol, too many subdomains, phishing-related words).
- **Suspicious Message Checker** — scans an email or text message for phishing warning signs (urgency, threats, generic greetings, money requests, requests for sensitive information).
- **Security Awareness Quiz** — a five-question multiple-choice quiz with instant feedback.
- **Incident Report Form & Log** — lets users report phishing incidents, saved to a database and viewable as a log with the most recent reports first.
- **Machine-Learning Demo** — a small Naive Bayes classifier, trained on a few labelled phishing and safe messages, shown alongside the rule-based checker so the two approaches can be compared.

## Tech stack

- **Python 3** with the **Flask** web framework
- **HTML & CSS** for the interface (templates rendered with Jinja2)
- **SQLite** for storing incident reports

The core detection is **rule-based** — defined checks and keyword lists keep the logic transparent and within scope. The Machine-Learning Demo adds a small, self-contained Naive Bayes classifier (written in plain Python, no external ML library) to illustrate how a learned model compares with fixed rules. See *Future Work* below.

## How to run it locally

1. Clone or download this repository.
2. Open a terminal in the project folder.
3. Create and activate a virtual environment (`python3 -m venv venv` then `source venv/bin/activate`).
4. Install the requirements with `pip install -r requirements.txt`.
5. Start the app with `python3 app.py`.
6. Open http://127.0.0.1:5001 in a browser.

The SQLite database (`phishguard.db`) is created automatically the first time the app runs.

## Project structure

The project contains `app.py` (Flask routes, detection logic, the Naive Bayes demo and database functions), a `static` folder for the CSS, and a `templates` folder holding the homepage and one page per feature.

## Future work

The core detection relies on fixed rules and keyword lists, and the machine-learning demo is trained on only a small set of examples. Natural next steps would be to train the model on a larger labelled phishing dataset so it recognises patterns the fixed rules miss, add user accounts, deploy the app to a public host, and expand the rule and keyword sets.

## Author

Student project for Professional Development (S2-PFD200).
