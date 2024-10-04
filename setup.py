from setuptools import Extension, setup, find_packages

twofish = Extension(
    "pgmm_decrypt._twofish",
    sources=["twofish-0.3/twofish.c", "twofish.c"],
    include_dirs=["twofish-0.3"],
)

setup(
    name="pgmm_decrypt",
    version="0.2.0",
    packages=find_packages(include=["pgmm_decrypt"]),
    ext_modules=[twofish],
)
