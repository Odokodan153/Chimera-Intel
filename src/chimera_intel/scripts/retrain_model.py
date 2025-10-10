import pandas as pd
from sqlalchemy import create_engine
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from transformers import (
    Trainer,
    TrainingArguments,
    DistilBertForSequenceClassification,
    DistilBertTokenizerFast,
)
import torch
import logging
import os

# Configure logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# --- Database Connection ---
# It's recommended to use environment variables for database credentials

DB_USER = os.getenv("DB_USER", "user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "password")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "chimera_intel")
DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"

engine = create_engine(DATABASE_URL)


def fetch_data():
    """Fetches negotiation messages from the database."""
    try:
        # Select messages that have a labeled intent

        query = "SELECT content as text, (analysis->>'intent') as intent FROM messages WHERE analysis->>'intent' IS NOT NULL;"
        df = pd.read_sql(query, engine)
        logger.info(f"Fetched {len(df)} records from the database for retraining.")
        return df
    except Exception as e:
        logger.error(f"Failed to fetch data from the database: {e}")
        return pd.DataFrame()


def main():
    """Main function to run the retraining pipeline."""
    df = fetch_data()
    if df.empty or len(df) < 10:  # Don't retrain on very small datasets
        logger.warning("Not enough data to retrain the model. Exiting.")
        return
    # --- Label Encoding for string intents ---

    le = LabelEncoder()
    df["intent_encoded"] = le.fit_transform(df["intent"])
    num_labels = len(le.classes_)

    train_texts, val_texts, train_labels, val_labels = train_test_split(
        df["text"].tolist(),
        df["intent_encoded"].tolist(),
        test_size=0.2,
        random_state=42,
    )

    # --- Tokenization ---

    tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")
    train_encodings = tokenizer(train_texts, truncation=True, padding=True)
    val_encodings = tokenizer(val_texts, truncation=True, padding=True)

    # --- PyTorch Dataset ---

    class NegotiationDataset(torch.utils.data.Dataset):
        def __init__(self, encodings, labels):
            self.encodings = encodings
            self.labels = labels

        def __getitem__(self, idx):
            item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
            item["labels"] = torch.tensor(self.labels[idx])
            return item

        def __len__(self):
            return len(self.labels)

    train_dataset = NegotiationDataset(train_encodings, train_labels)
    val_dataset = NegotiationDataset(val_encodings, val_labels)

    # --- Model Fine-Tuning ---

    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased", num_labels=num_labels
    )

    training_args = TrainingArguments(
        output_dir="./results",
        num_train_epochs=3,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=64,
        warmup_steps=500,
        weight_decay=0.01,
        logging_dir="./logs",
        logging_steps=10,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
    )

    logger.info("Starting model fine-tuning...")
    trainer.train()
    logger.info("Training complete.")

    # --- Save the fine-tuned model for deployment ---

    model_path = "./models/negotiation_intent_model"
    trainer.save_model(model_path)
    tokenizer.save_pretrained(model_path)
    logger.info(f"Model and tokenizer saved to {model_path}")


if __name__ == "__main__":
    main()
