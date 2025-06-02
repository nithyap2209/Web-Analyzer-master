import os
import logging
import time
import traceback
import razorpay
from dotenv import load_dotenv

# Configure more detailed logging
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for most detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Load environment variables from .env file
load_dotenv()

def debug_razorpay_setup():
    """
    Comprehensive debugging for Razorpay setup
    """
    # Print environment variable debugging info
    logging.debug("Debugging Razorpay Configuration:")
    
    # Check .env file loading
    env_path = os.path.join(os.getcwd(), '.env')
    logging.debug(f"Looking for .env file at: {env_path}")
    logging.debug(f".env file exists: {os.path.exists(env_path)}")

    # Retrieve and log credentials (be careful not to expose full secret in production)
    key_id = os.getenv('RAZORPAY_KEY_ID')
    key_secret = os.getenv('RAZORPAY_KEY_SECRET')
    
    logging.debug(f"RAZORPAY_KEY_ID retrieved: {'Yes' if key_id else 'No'}")
    if not key_id:
        logging.error("RAZORPAY_KEY_ID is missing from environment variables")
    
    logging.debug(f"RAZORPAY_KEY_SECRET retrieved: {'Yes' if key_secret else 'No'}")
    if not key_secret:
        logging.error("RAZORPAY_KEY_SECRET is missing from environment variables")

    # Attempt Razorpay client initialization
    try:
        # Initialize the Razorpay client
        logging.debug("Attempting to initialize Razorpay client...")
        client = razorpay.Client(auth=(key_id, key_secret))
        
        # Test order creation
        logging.debug("Attempting to create test order...")
        test_order = client.order.create({
            'amount': 100,  # 1 INR (amount in paisa)
            'currency': 'INR',
            'receipt': f'debug_order_{int(time.time())}',
            'payment_capture': 1
        })
        
        logging.info("Razorpay client initialization successful!")
        logging.info(f"Test order created: {test_order['id']}")
        
        return client
    
    except Exception as e:
        logging.error("Razorpay client initialization failed:")
        logging.error(f"Error Type: {type(e).__name__}")
        logging.error(f"Error Details: {str(e)}")
        logging.debug("Full traceback:")
        traceback.print_exc()
        return None

def main():
    """
    Main debugging function
    """
    logging.info("Starting Razorpay Configuration Debug")
    client = debug_razorpay_setup()
    
    if not client:
        logging.error("Failed to initialize Razorpay client. Please check the above error messages.")

if __name__ == '__main__':
    main()
    