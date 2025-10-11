#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Setup configuration for Ansible ZeroSSL Plugin
"""

from setuptools import setup, find_packages
import os


# Read long description from README
def read_readme():
    readme_path = os.path.join(os.path.dirname(__file__), "README.md")
    if os.path.exists(readme_path):
        with open(readme_path, "r", encoding="utf-8") as f:
            return f.read()
    return "Ansible ZeroSSL Certificate Management Plugin"


setup(
    name="ansible-zerossl",
    version="1.0.0",
    description="Ansible action plugin for ZeroSSL certificate management",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    author="Ansible ZeroSSL Plugin Contributors",
    author_email="noreply@example.com",
    url="https://github.com/your-org/ansible-zerossl",
    # Python version requirement
    python_requires=">=3.12",
    # Package discovery
    packages=find_packages(include=["module_utils*"]),
    # Include non-Python files
    include_package_data=True,
    package_data={
        "": ["*.md", "*.txt", "*.yml", "*.yaml"],
    },
    # Dependencies
    install_requires=[
        "ansible>=8.0.0",
        "requests>=2.31.0",
        "cryptography>=41.0.0",
    ],
    # Optional dependencies for development
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-ansible>=4.0.0",
            "pytest-mock>=3.11.0",
            "flake8>=6.0.0",
            "black>=23.0.0",
            "mypy>=1.5.0",
        ],
        "docs": [
            "sphinx>=7.1.0",
            "sphinx-rtd-theme>=1.3.0",
        ],
    },
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Systems Administration",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    # Keywords
    keywords="ansible ssl certificate zerossl automation devops",
    # Entry points (if needed for CLI tools)
    entry_points={
        "console_scripts": [
            # Add CLI scripts here if needed
        ],
    },
)
