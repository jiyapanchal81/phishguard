# ml_model.py
# A small machine-learning demo for PhishGuard.
# This is an exploratory learning experiment, not production-grade.
# It uses a simple Naive Bayes classifier trained on a tiny dataset.

import math


# ---------------- TRAINING DATA ----------------
# Each item is (message, label). The model learns from these examples.

TRAINING_DATA = [
    ("Dear customer, your account has been suspended. Verify your identity immediately to avoid closure.", "phishing"),
    ("Congratulations! You have won a free gift card. Click here to claim your prize now.", "phishing"),
    ("Urgent: your payment failed. Update your card details within 24 hours or lose access.", "phishing"),
    ("Your package could not be delivered. Confirm your address and pay a small fee here.", "phishing"),
    ("We detected unusual login activity. Reset your password now using this link.", "phishing"),
    ("You are the lucky winner of our lottery. Send your bank details to receive your cash reward.", "phishing"),
    ("Final notice: your subscription will be cancelled unless you confirm your billing now.", "phishing"),
    ("Security alert: someone accessed your account. Verify your login details here immediately.", "phishing"),
    ("Dear user, click the link below to restore your blocked account before it is deleted.", "phishing"),
    ("Action required: confirm your identity or your account will be permanently locked.", "phishing"),
    ("Your tax refund is ready. Provide your bank account number to claim it today.", "phishing"),
    ("Limited time offer! Claim your free gift now before this exclusive deal expires.", "phishing"),
    ("Important: your card has been blocked. Call this number and confirm your pin now.", "phishing"),
    ("Account verification needed. Failure to act now will result in suspension of your services.", "phishing"),
    ("Win a brand new phone today! Just enter your details and claim your prize instantly.", "phishing"),
    ("Hi, just confirming our meeting tomorrow at 2pm in the main office. See you then.", "safe"),
    ("Thanks for your email. I have attached the report you asked for. Let me know your thoughts.", "safe"),
    ("Reminder: the team lunch is on Friday. Please let me know if you can make it.", "safe"),
    ("Your order has shipped and should arrive within three working days. Thank you for shopping with us.", "safe"),
    ("Hi mum, I will be home late tonight, do not wait up for dinner. Love you.", "safe"),
    ("Great work on the presentation today. The client was really impressed.", "safe"),
    ("The library books you reserved are now ready for collection at the front desk.", "safe"),
    ("Happy birthday! Hope you have a wonderful day and enjoy the weekend.", "safe"),
    ("Your appointment with the dentist is confirmed for Monday at 10am.", "safe"),
    ("Thanks for joining the call earlier. I will send the notes round shortly.", "safe"),
    ("The weather looks good for the weekend, shall we go for a walk on Saturday?", "safe"),
    ("Your monthly statement is now available to view in your online account.", "safe"),
    ("Congratulations on passing your exam, all your hard work paid off.", "safe"),
    ("I have booked the room for our study session on Thursday afternoon.", "safe"),
    ("Our office will be closed on the bank holiday. Normal hours resume on Tuesday.", "safe"),
]


# ---------------- THE CLASSIFIER ----------------

def tokenize(text):
    """Turn a message into a list of lowercase words, ignoring punctuation."""
    cleaned = ""
    for character in text.lower():
        if character.isalpha() or character == " ":
            cleaned += character
        else:
            cleaned += " "
    return cleaned.split()


def train():
    """Learn from the training data by counting word frequencies per class."""
    word_counts = {"phishing": {}, "safe": {}}
    class_counts = {"phishing": 0, "safe": 0}
    vocabulary = set()

    for message, label in TRAINING_DATA:
        class_counts[label] += 1
        for word in tokenize(message):
            vocabulary.add(word)
            word_counts[label][word] = word_counts[label].get(word, 0) + 1

    return word_counts, class_counts, vocabulary


# Train the model once, when this file is first loaded.
MODEL = train()


def classify_message(message):
    """Predict whether a message is phishing or safe, using the trained model."""
    word_counts, class_counts, vocabulary = MODEL
    total_messages = class_counts["phishing"] + class_counts["safe"]
    vocab_size = len(vocabulary)

    scores = {}
    for label in ("phishing", "safe"):
        # Start with the prior: how common this class is overall (in log form).
        score = math.log(class_counts[label] / total_messages)
        words_in_class = sum(word_counts[label].values())
        for word in tokenize(message):
            # Add-one smoothing: every word gets at least a tiny probability.
            count = word_counts[label].get(word, 0)
            probability = (count + 1) / (words_in_class + vocab_size)
            score += math.log(probability)
        scores[label] = score

    # The class with the higher score is the prediction.
    if scores["phishing"] >= scores["safe"]:
        prediction = "phishing"
    else:
        prediction = "safe"

    # Convert the two log-scores into a confidence percentage.
    highest = max(scores["phishing"], scores["safe"])
    phishing_weight = math.exp(scores["phishing"] - highest)
    safe_weight = math.exp(scores["safe"] - highest)
    total_weight = phishing_weight + safe_weight
    if prediction == "phishing":
        confidence = round(phishing_weight / total_weight * 100)
    else:
        confidence = round(safe_weight / total_weight * 100)

    return {"prediction": prediction, "confidence": confidence}


# ---------------- QUICK STANDALONE TEST ----------------
# This runs only when you run this file directly (python3 ml_model.py).
# It does NOT run when app.py imports the classifier.

if __name__ == "__main__":
    test1 = "Urgent: verify your account now or it will be suspended."
    test2 = "Hi, are we still meeting for coffee tomorrow afternoon?"
    print("Test 1 (expected phishing):", classify_message(test1))
    print("Test 2 (expected safe):    ", classify_message(test2))
