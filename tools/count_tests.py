import pytest

class CountPlugin:
    def __init__(self):
        self.collected = 0

    def pytest_collection_finish(self, session):
        self.collected = len(session.items)
        print(f"COLLECTED_TOTAL_TESTS={self.collected}")

if __name__ == "__main__":
    plugin = CountPlugin()
    pytest.main(["--collect-only", "-q"], plugins=[plugin])
