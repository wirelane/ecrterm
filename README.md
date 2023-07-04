[![Build Status](https://travis-ci.org/karolyi/py3-ecrterm.svg?branch=master)](https://travis-ci.org/karolyi/py3-ecrterm)

ecrterm
=======

Python ZVT 700 interface (electronic cash registers)

# Creating tags and releases
Based on https://stackoverflow.com/a/7502821

Update the version in [ecrterm/__init__.py](ecrterm/__init__.py), then create a tag using
```
git tag -a v$(python setup.py --version) -m 'description of version'
```
Use this tag to create a release with the same version in github afterwards.
