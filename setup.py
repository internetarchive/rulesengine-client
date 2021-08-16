from setuptools import setup


setup(
    name='rulesengine_client',
    description='Client for interacting with the playback Rules Engine',
    version='0.5',
    install_requires=[
        'psycopg2',
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
    author='Barbara Miller <barbara@archive.org>, Madison Scott-Clary',
    author_email='barbara@archive.org',
    license='GPLv3')
