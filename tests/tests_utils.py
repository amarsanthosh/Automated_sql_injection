import unittest
from utils import validate_url, log_message

class TestUtils(unittest.TestCase):

    def test_validate_url(self):
        # Test valid URLs
        self.assertTrue(validate_url("http://example.com"))
        self.assertTrue(validate_url("https://example.com"))
        
        # Test invalid URLs
        self.assertFalse(validate_url("ftp://example.com"))
        self.assertFalse(validate_url("example.com"))

    def test_log_message(self):
        # Test that log_message doesn't raise any errors
        try:
            log_message("This is an info message", level="info")
            log_message("This is a warning message", level="warning")
            log_message("This is an error message", level="error")
            log_message("This is a debug message", level="debug")
        except Exception as e:
            self.fail(f"log_message raised an exception: {e}")

if __name__ == "__main__":
    unittest.main()
