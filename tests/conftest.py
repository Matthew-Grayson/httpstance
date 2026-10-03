import pytest


def pytest_addoption(parser):
    parser.addoption("--live", action="store_true", default=False,
                     help="run tests that make real network connections")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--live"):
        return
    skip = pytest.mark.skip(reason="requires flag: --live")
    for item in items:
        if "live" in item.keywords:
            item.add_marker(skip)


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_logreport(report):
    """Show test names instead of line numbers in the -rs skip summary.

    This rewrites report.longrepr, whose (path, lineno, reason) tuple shape is
    pytest internals rather than public API. Verified against pytest 9.1.1; if
    the skip summary starts raising or formatting oddly after a pytest upgrade,
    delete this hook rather than debugging it.
    """
    if report.outcome == "skipped" and isinstance(report.longrepr, tuple):
        filepath, lineno, reason = report.longrepr

        # Extract the actual test name from the unique nodeid
        test_name = report.nodeid.split("::")[-1]

        # Replace the line number with the test function name
        report.longrepr = (filepath, test_name, reason)