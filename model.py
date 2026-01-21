import numpy as np
import re
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.optimizers import Adam

data = pd.read_csv("phishing_mail_dataset.csv")
data = data[["text","label"]]

def clean_text(text):
    text = text.lower()
    text = re.sub(r"[^a-z\s]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text

data["text"] = [clean_text(t) for t in data["text"]]
tfidf = TfidfVectorizer(
    max_features=2000,
    ngram_range=(1, 2),
    stop_words="english"
)

X = tfidf.fit_transform(data["text"]).toarray()
y = data["label"] 
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.3, random_state=42
)

model = Sequential([
    Dense(256, activation="relu", input_shape=(X_train.shape[1],)),
    Dropout(0.5),
    Dense(128, activation="relu"),
    Dropout(0.5),
    Dense(len(np.unique(y)), activation="softmax")
])

model.compile(
    optimizer=Adam(learning_rate=1e-3),
    loss="sparse_categorical_crossentropy",
    metrics=["accuracy"]
)
history = model.fit(
    X_train,
    y_train,
    epochs=20,
    batch_size=16,
    validation_split=0.1,
    verbose=1
)
model.save("model.h5")

joblib.dump(tfidf, "tfidf_vectorizer.pkl")


y_pred = np.argmax(model.predict(X_test), axis=1)

print("Accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(
    y_test, y_pred
))


########connect in flask

def clean_text(text):
    text = text.lower()
    text = re.sub(r"[^a-z\s]", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text
from tensorflow.keras.models import load_model
import joblib
import numpy as np
import re
def classify_text(text):
    model = load_model("model.h5")
    tfidf = joblib.load("tfidf_vectorizer.pkl")
    text = clean_text(text)
    vector = tfidf.transform([text]).toarray()
    prediction = np.argmax(model.predict(vector), axis=1)[0]
    return prediction

# Example
print(classify_text("Subject: Office maintenance Thanks for your help on the analysis. I've pushed the changes and left comments in the PR for clarity. Let me know if the timing works for you. Best,  Avery Kim"))
print(classify_text("Hello, your profile has been locked. Use the secure link to verify your username and restore access. Enter your verification code to continue.Keywords: pin update password sign in settings passwordSincerely, Riley Khan"))

