
from setuptools import setup, find_packages

setup(
    name="cryptocore",
    version="1.0.0",
    description="AES-128 ECB file encryption tool",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "pycryptodome>=3.20.0",
    ],
    entry_points={
        "console_scripts": [
            "cryptocore=main:main",
        ],
    },
    python_requires=">=3.6",
)