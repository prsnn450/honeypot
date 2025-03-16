from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

# Load the tokenizer and model from the downloaded directory
MODEL_PATH = "C:/Users/build/Downloads/flask_app/model"  # Path to the downloaded model
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)

def test_sql_injection_model(input_strings):
    """
    Test the Hugging Face model with example strings.

    Args:
        input_strings (list): A list of strings to test.

    Returns:
        list: A list of tuples containing the input string, prediction (True/False), and confidence score.
    """
    results = []

    for input_string in input_strings:
        # Tokenize the input string
        inputs = tokenizer(input_string, return_tensors="pt", truncation=True, padding=True, max_length=512)

        # Make predictions
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=-1)  # Convert logits to probabilities
            confidence, predicted_class = torch.max(probabilities, dim=-1)

        # Interpret the prediction
        is_sqli = predicted_class.item() == 1  # Assuming class 1 is SQL injection
        confidence_score = confidence.item()

        results.append((input_string, is_sqli, confidence_score))

    return results

# Example usage
if __name__ == "__main__":
    # Example strings to test
    test_strings = [
        "SELECT * FROM users WHERE username='admin' or '1' AND password='password'",  # Legitimate query
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