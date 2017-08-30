from setuptools import setup, find_packages


def readme():
    with open('README.md') as f:
        return f.read()


setup(
    name='uniflex_module_wifi_flex',
    version='0.1.0',
    packages=find_packages(),
    url='https://github.com/wishful-project/wishrem_wifi_flex',
    license='Apache 2.0',
    author='Daniel Denkovski',
    author_email='danield@feit.ukim.edu.mk',
    description='UniFlex WIFI Flex Module',
    long_description='UniFlex WIFI Flex Module',
    keywords='wireless control, mode configuration, sensing',
    install_requires=['pyric', 'pyshark']
)
