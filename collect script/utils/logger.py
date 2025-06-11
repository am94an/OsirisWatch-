# utils/logger.py

import logging

def setup_logger():
    logger = logging.getLogger('IDSLogger')
    logger.setLevel(logging.DEBUG)

    fh = logging.FileHandler('ids.log')
    fh.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger