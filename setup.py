"""
Setup script for SecFixAI.
"""

from setuptools import setup, find_packages

setup(
    name="secfixai",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "openai==1.70.0",
        "PyGithub==2.6.1",
        "requests==2.32.3",
        "google-generativeai==0.8.4",
        "ipython==8.27.0",
        "huggingface_hub[inference]==0.30.2",
        "bandit==1.7.5",
        "colorama==0.4.6",
        "tabulate==0.9.0",
        "flask==3.0.0",
        "flask-wtf==1.2.1",
        "flask-bootstrap==3.3.7.1",
    ],
    entry_points={
        "console_scripts": [
            "secfixai=core.runner:main",
            "secfixai-web=run_web:main",
        ],
    },
)
