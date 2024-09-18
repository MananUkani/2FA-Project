import logging
from logging.handlers import RotatingFileHandler

def setup_logging():
    handler = RotatingFileHandler('error.log', maxBytes=10000, backupCount=1)
    handler.setLevel(logging.ERROR)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    handler.setFormatter(formatter)
    
    app_logger = logging.getLogger('werkzeug')  # Flask's default logger
    app_logger.addHandler(handler)
    app_logger.setLevel(logging.ERROR)

    # Add the handler to the Flask app logger
    flask_logger = logging.getLogger('flask.app')
    flask_logger.addHandler(handler)
    flask_logger.setLevel(logging.ERROR)
