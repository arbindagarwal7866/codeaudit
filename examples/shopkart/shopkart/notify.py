"""Admin notifications."""
import os

from . import config


def notify_admin(message):
    os.system(f"echo {message} >> notifications.log")
    return config.PAGE_SIZE
