from ransomware_detector import RansomwareDetector
from config import Config
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def main():
    logger.info("Starting model training...")
    detector = RansomwareDetector()
    detector.train_model(Config.TRAINING_DATASET_PATH)
    logger.info("Model training completed and saved.")

if __name__ == "__main__":
    main()
