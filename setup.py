from setuptools import setup, find_packages

setup(
    name="secure-password-manager",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        'cryptography>=3.4.7',
        'pillow>=8.0.0',
    ],
    entry_points={
        'console_scripts': [
            'password-manager=main:main',
        ],
    },
    author="ThenerzZ",
    description="A secure password manager with modern UI",
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url="https://github.com/ThenerzZ/password_generator",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.8',
) 