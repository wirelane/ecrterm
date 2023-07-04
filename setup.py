from setuptools import find_packages, setup

from ecrterm import __version__

setup(
    name='py3-ecrterm',
    version=__version__,
    packages=find_packages(exclude=['ecrterm.tests']),
    license='LGPL-3',
    install_requires=[
        'backcall==0.1.0',
        'decorator==4.3.0',
        'flake8==3.5.0',
        'ipython==6.3.1',
        'ipython-genutils==0.2.0',
        'isort==4.3.4',
        'jedi==0.12.0',
        'mccabe==0.6.1',
        'parso==0.2.0',
        'pexpect==4.5.0',
        'pickleshare==0.7.4',
        'prompt-toolkit==1.0.15',
        'ptyprocess==0.5.2',
        'pycodestyle==2.3.1',
        'pyflakes==1.6.0',
        'Pygments==2.2.0',
        'pyserial==3.4',
        'simplegeneric==0.8.1',
        'six==1.11.0',
        'traitlets==4.3.2',
        'wcwidth==0.1.7',
        'unittest_data_provider==1.0.1',
    ],
    include_package_data=True,
    classifiers=[
        'License :: OSI Approved :: GNU Lesser General Public License v3 or '
        'later (LGPLv3+)',
    ],
)
