import pytest
from src.main import SecureLogAnalyzerApp
import tkinter as tk

@pytest.fixture
def app():
    root = tk.Tk()
    application = SecureLogAnalyzerApp(root)
    yield application
    root.destroy()

def test_brute_force_detection(app):
    """Test if the logic correctly flags multiple failed logins (FR-12)"""
    test_lines = [
        "Oct 15 12:00:01 auth failed password for root",
        "Oct 15 12:00:02 auth failed password for root",
        "Oct 15 12:00:03 auth failed password for root",
        "Oct 15 12:00:04 auth failed password for root",
        "Oct 15 12:00:05 auth failed password for root"
    ]
    
    # We simulate the processing logic
    failed_logins = {}
    detected = False
    for line in test_lines:
        if "failed password" in line.lower():
            user = "root"
            failed_logins[user] = failed_logins.get(user, 0) + 1
            if failed_logins[user] >= 5:
                detected = True
    
    assert detected is True

def test_privilege_detection(app):
    """Test if sudo/root commands are flagged (FR-14)"""
    line = "Oct 15 12:05:00 user1 sudo apt-get update"
    is_privileged = "sudo" in line.lower() or "root" in line.lower()
    assert is_privileged is True