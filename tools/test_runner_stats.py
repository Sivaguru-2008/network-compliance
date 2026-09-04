import pytest

class StatsPlugin:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.xfailed = 0
        self.xpassed = 0
        self.warnings = 0

    def pytest_runtest_logreport(self, report):
        if report.when == "call":
            if report.passed:
                if hasattr(report, "wasxfail"):
                    self.xpassed += 1
                else:
                    self.passed += 1
            elif report.failed:
                if hasattr(report, "wasxfail"):
                    self.xfailed += 1
                else:
                    self.failed += 1
            elif report.skipped:
                self.skipped += 1
        elif report.when == "setup" and report.skipped:
            self.skipped += 1

    def pytest_warning_recorded(self, warning_message, when, nodeid, location):
        self.warnings += 1

    def pytest_sessionfinish(self, session, exitstatus):
        print(f"\n--- PYTEST EXACT SUMMARY ---")
        print(f"PASSED: {self.passed}")
        print(f"FAILED: {self.failed}")
        print(f"SKIPPED: {self.skipped}")
        print(f"XFAILED: {self.xfailed}")
        print(f"XPASSED: {self.xpassed}")
        print(f"WARNINGS: {self.warnings}")
        print(f"TOTAL EXECUTED/RECORDED: {self.passed + self.failed + self.skipped + self.xfailed}")

if __name__ == "__main__":
    plugin = StatsPlugin()
    pytest.main(["-q", "--tb=no"], plugins=[plugin])
