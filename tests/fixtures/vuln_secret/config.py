"""Vulnerable fixture: hardcoded secret + secret logged."""
import logging

log = logging.getLogger(__name__)

SECRET_KEY = "s3cr3t-hardcoded-value-9f8a7b6c"   # hardcoded credential
API_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"  # value-shape match


def connect(password):
    log.info("connecting with password %s", password)   # secret in log
