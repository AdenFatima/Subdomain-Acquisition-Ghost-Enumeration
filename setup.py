from setuptools import setup, find_packages
from pathlib import Path

def read_requirements():
    req_file = Path(__file__).resolve().parent / "requirements.txt"
    if req_file.exists():
        with open(req_file, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return []

setup(
    name="sage",
    version="1.0.0",
    description="Subdomain Acquisition & Ghost Enumeration Tool",
    packages=find_packages(),
    py_modules=["sage"],
    install_requires=read_requirements(),
    entry_points={
        "console_scripts": [
            "sage=sage:cli",
        ],
    },
)