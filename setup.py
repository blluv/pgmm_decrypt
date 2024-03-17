from setuptools import setup, find_packages

setup(
    name="pgmm_decrypt",
    version="0.1.0",
    packages=find_packages(include=["pgmm_decrypt"]),
    install_requires=["twofish"],
)
