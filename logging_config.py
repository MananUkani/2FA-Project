import logging
from logging.handlers import RotatingFileHandler

def setup_logging():
    # Create a rotating file handler
    handler = RotatingFileHandler('error.log', maxBytes=10000, backupCount=1)
    handler.setLevel(logging.ERROR)  # Only log errors and above
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)

    # Flask's default logger for handling HTTP requests
    app_logger = logging.getLogger('werkzeug')  
    app_logger.addHandler(handler)
    app_logger.setLevel(logging.ERROR)

    # Flask app logger
    flask_logger = logging.getLogger('flask.app')
    flask_logger.addHandler(handler)
    flask_logger.setLevel(logging.ERROR)

    # Also log uncaught exceptions in the application
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.ERROR)

    # Log a message to confirm logging has been set up
    flask_logger.error("Logging is set up and running.")
