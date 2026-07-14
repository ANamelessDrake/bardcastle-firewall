from setuptools import setup, find_packages

setup(
    name="bardcastle-firewall",
    version="1.0.0",
    packages=find_packages(),
    include_package_data=True,
    package_data={"": ["templates/**/*"]},
    install_requires=[
        "click>=8.0",
        "jinja2>=3.0",
        "pyyaml>=6.0",
        "jblib>=1.11",
    ],
    entry_points={
        "console_scripts": [
            "bardcastle-fw=bardcastle.cli:main",
        ],
    },
)
