import os
os.environ.setdefault("AUTH_MODE", "header")   # legacy tests use the demo identity header; test_auth.py opts into token mode explicitly
