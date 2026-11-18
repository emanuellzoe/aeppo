from setuptools import find_packages, setup


setup(
    name="aeppo",
    version="0.1.0",
    description="Local static scanner for risky source patterns and exposed secrets",
    url="https://github.com/emanuellzoe/aeppo",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    python_requires=">=3.9",
    entry_points={"console_scripts": ["aeppo=aeppo.cli:main"]},
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Topic :: Security",
    ],
)
