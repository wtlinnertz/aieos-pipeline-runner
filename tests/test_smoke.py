from aieos_pipeline_runner import __version__


def test_package_exposes_version_string() -> None:
    assert isinstance(__version__, str)
    assert __version__
