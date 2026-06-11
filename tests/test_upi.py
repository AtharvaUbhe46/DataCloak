from datacloak.detectors.upi import UPIDetector

def test_email_not_detected_as_upi():
    detector = UPIDetector()
    text = "Email: rahul.sharma@example.com"
    matches = detector.detect(text)
    assert matches == []

def test_upi_and_email_together():
    detector = UPIDetector()
    text = """
    Email: rahul.sharma@example.com
    UPI: rahul@okaxis
    """
    matches = detector.detect(text)
    values = [m.value for m in matches]
    assert values == ["rahul@okaxis"]