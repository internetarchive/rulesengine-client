from setuptools import setup


setup(
    name='rulesengine_client',
    description='Client for interacting with the Playback Rules Engine',
    version='0.1.0',
    install_requires=[
        'python-dateutil',
        'ipaddr',
        'pytz',
        'requests',
    ],
    tests_require=[
        'mock',
    ],
    packages=[
        'rulesengine_client',
    ],
    test_suite='rulesengine_client.tests',
    author='Madison Scott-Clary',
    author_email='madison@archive.org',
    license='GPLv3')
