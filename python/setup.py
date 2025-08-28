from setuptools import setup, find_packages

setup(
    name="salman-40-crypto-sdk",
    version="2.0.0",
    description="Production-grade cryptographic SDK for salman 40",
    packages=find_packages(),
    install_requires=[
        "cryptography>=3.0.0",
    ],
    python_requires=">=3.7",
)