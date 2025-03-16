import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences
import joblib

# Load the trained CNN model and tokenizer
MODEL_PATH = "sqli_cnn_model.h5"
TOKENIZER_PATH = "tokenizer.pkl"

# Load the model and tokenizer
model = tf.keras.models.load_model(MODEL_PATH)
tokenizer = joblib.load(TOKENIZER_PATH)

def test_sql_injection_model(input_strings):
    """
    Test the SQL Injection CNN model with example strings.

    Args:
        input_strings (list): A list of strings to test.

    Returns:
        list: A list of tuples containing the input string, prediction (True/False), and confidence score.
    """
    results = []

    # Tokenize and pad the input strings
    sequences = tokenizer.texts_to_sequences(input_strings)
    padded_sequences = pad_sequences(sequences, maxlen=100, padding='post')

    # Make predictions
    predictions = model.predict(padded_sequences)

    for i, input_string in enumerate(input_strings):
        prediction_prob = predictions[i][0]
        is_sqli = prediction_prob > 0.5  # Threshold for classification
        confidence = prediction_prob if is_sqli else 1 - prediction_prob
        results.append((input_string, is_sqli, confidence))

    return results

# Example usage
if __name__ == "__main__":
    # Example strings to test
    test_strings = [
        "SELECT * FROM users WHERE username='admin' AND password='password'",  # Legitimate query
        "1' OR '1'='1",  # SQL Injection attempt
        "DROP TABLE users;",  # SQL Injection attempt
        "Hello, world!",  # Normal string
        "admin' --",  # SQL Injection attempt
    ]

    # Test the model
    results = test_sql_injection_model(test_strings)

    # Print results
    for input_string, is_sqli, confidence in results:
        print(f"Input: {input_string}")
        print(f"SQL Injection Detected: {is_sqli}")
        print(f"Confidence: {confidence:.4f}")
        print("-" * 50)
