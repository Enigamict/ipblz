from setuptools import setup
from setuptools import setup, find_packages

setup(
    name='ipblz',
    version='0.0.1',
    description='Helping you get closer to the network',
    #long_description=readme,
    author='Enigamict',
    url='https://github.com/Enigamict/ipblz',
    license=license,
    packages=find_packages(exclude=('tests', 'docs'))
)