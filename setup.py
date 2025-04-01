from setuptools import setup, find_namespace_packages

setup(
    name='visionlab-auth',
    version='0.1.0',
    packages=['visionlab.auth'],
    package_dir={'visionlab.auth': 'auth'},
    python_requires='>=3.3',
    # Other metadata such as classifiers, description, etc.
)