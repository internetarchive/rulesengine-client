from setuptools import setup


setup(
    name='rulesengine_client',
    description='Client for interacting with the Playback Rules Engine',
    version='0.1',
    install_requires=[
        'requests',
    ],
    test_requires=[
        'mock',
        'requests',
    ],
    packages=[
        'rulesengine_client',
    ],
    test_suite='rulesengine_client.tests',
    author='Madison Scott-Clary',
    author_email='madison@archive.org',
    license='GPLv3')
