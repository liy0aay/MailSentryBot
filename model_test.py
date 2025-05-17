from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

tokenizer = AutoTokenizer.from_pretrained("ealvaradob/bert-finetuned-phishing")
model = AutoModelForSequenceClassification.from_pretrained("ealvaradob/bert-finetuned-phishing")

text = "Your account has been compromised! Click here immediately to reset your password: http://fake-bank-login.com"
inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
outputs = model(**inputs)
logits = outputs.logits
predicted_class_id = torch.argmax(logits).item()
print("Predicted class ID:", predicted_class_id)
