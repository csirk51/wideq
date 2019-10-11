from setuptools import setup


setup(
    name='wideq_hu',
    version='0.0.6',
    description='LG SmartThinQ API client for Hungarian',
    author='wkd8176',
    author_email='wkd8176@gmail.com',
    url='https://github.com/csirk51/wideq',
    license='MIT',
    platforms='ALL',
    install_requires=['requests'],
    py_modules=['wideq'],
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
    ],
)
