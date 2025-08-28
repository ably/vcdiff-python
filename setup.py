from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="ably-vcdiff-decoder",
    version="1.0.0",
    author="Ably Realtime Limited",
    author_email="support@ably.io",
    description="Python implementation of VCDIFF (RFC 3284) delta compression format",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/ably/vcdiff-py",
    project_urls={
        "Bug Reports": "https://github.com/ably/vcdiff-py/issues",
        "Source": "https://github.com/ably/vcdiff-py",
        "Documentation": "https://github.com/ably/vcdiff-py#readme",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Archiving :: Compression",
        "Topic :: Utilities",
    ],
    keywords="vcdiff, delta, compression, rfc3284, ably",
    python_requires=">=3.8",
    install_requires=[
        "click>=8.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "vcdiff=vcdiff.cli:main",
        ],
    },
)