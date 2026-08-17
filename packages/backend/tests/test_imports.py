"""
Import smoke tests.

The last several boot failures were broken imports in modules that nothing in
the test suite touched. This walks every module under app.jobs and
app.services (and imports app.main itself) so a broken import in any of them
fails CI even if the module is not otherwise exercised.
"""

import importlib
import pkgutil

import pytest


def _walk_module_names(package_name: str) -> list[str]:
    """All module names under a package, without importing the leaf modules."""
    package = importlib.import_module(package_name)
    names = [package_name]
    # onerror keeps collection alive if a sub-package itself fails to import;
    # the parametrized test for that sub-package will then fail visibly.
    for info in pkgutil.walk_packages(
        package.__path__, prefix=package.__name__ + ".", onerror=lambda name: None
    ):
        names.append(info.name)
    return names


def test_app_main_imports():
    importlib.import_module("app.main")


@pytest.mark.parametrize(
    "module_name",
    _walk_module_names("app.jobs") + _walk_module_names("app.services"),
)
def test_module_imports(module_name: str):
    importlib.import_module(module_name)
