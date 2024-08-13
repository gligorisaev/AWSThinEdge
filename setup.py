from setuptools import setup, find_packages

setup(
    name='AWSThinEdge',
    version='0.2.1',
    description='A Robot Framework library for interacting with AWS IoT Core in the context of testing thin-edge.io.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/gligorisaev/AWSThinEdge.git',
    author='Gligor Isaev',
    author_email='gligorisaev@gmail.com',
    license='MIT',
    packages=find_packages(),
    install_requires=[
        'robotframework',
        'paho-mqtt',
        'dateparser',
    
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Framework :: Robot Framework',
    ],
    python_requires='>=3.6',
)
