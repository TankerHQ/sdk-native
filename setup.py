import sys
from setuptools import setup, find_packages

if sys.version_info.major < 3:
    sys.exit("Error: Please upgrade to Python3")


setup(
    name="Native",
    version="0.1.0",
    author="tech@tanker.io",
    packages=find_packages(),
    install_requires=[
        "ci",
    ],
    extras_require={
        "dev": [
        ]
    },
    classifiers=[
    ],
    entry_points={
        "console_scripts": []
    },
)
