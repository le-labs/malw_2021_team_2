from setuptools import setup
from Cython.Build import cythonize


setup(
    ext_modules = cythonize("netcat.pyx"),
)

# build with python setup.py build_ext --inplace
