import logging
from logging.handlers import RotatingFileHandler

def setup_logging():
    # Use absolute path for Azure App Service
    log_path = '/home/site/wwwroot/error.log'
    
    # Create a rotating file handler
    handler = RotatingFileHandler(log_path, maxBytes=10000, backupCount=1)
    handler.setLevel(logging.ERROR)  # Only log errors and above
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    
    # Flask's default logger for handling HTTP requests
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.addHandler(handler)
    werkzeug_logger.setLevel(logging.ERROR)
    
    # Flask app logger
    flask_logger = logging.getLogger('flask.app')
    flask_logger.addHandler(handler)
    flask_logger.setLevel(logging.ERROR)
    
    # Also log uncaught exceptions in the application
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.ERROR)

    # Log a message to confirm logging has been set up
    root_logger.error("Logging is set up and running.")
