from setuptools import setup, find_packages
from setuptools.command.test import test as SetuptoolsTestCommand
from shlex import split
from sys import version_info

class RunTestsCommand(SetuptoolsTestCommand):
    user_options = [
        ('only=', 'o', 'Only run the specified tests'),
        ('level=', 'l', 'Verbosity level; 0=minimal output, 1=normal output, 2=verbose output, 3=very verbose output'),
        ('suppress-coverage-report', None, 'Suppress coverage report'),
    ]
    def initialize_options(self):
        SetuptoolsTestCommand.initialize_options(self)
        self.test_suite = "override"
        self.only = ""
        self.level = "1"
        self.suppress_coverage_report = None

    def finalize_options(self):
        SetuptoolsTestCommand.finalize_options(self)
        self.test_suite = None
        self.level = int(self.level)
        self.suppress_coverage_report = self.suppress_coverage_report is not None

    def run(self):
        SetuptoolsTestCommand.run(self)
        self.with_project_on_sys_path(self.run_tests)

    def run_tests(self):
        import coverage.cmdline
        import os
        import subprocess
        import sys
        import time

        owd = os.path.abspath(os.getcwd())
        nwd = os.path.abspath(os.path.dirname(__file__))
        os.chdir(nwd)
        tests = split(self.only)
        if not tests:
            tests.extend([nwd, os.path.abspath('test_project')])
        errno = coverage.cmdline.main(['run', os.path.abspath('test_project/manage.py'), 'test', '--verbosity=%d' % self.level] + tests)

        if not self.suppress_coverage_report:
            coverage.cmdline.main(['report', '-m'])

        if None not in [os.getenv("TRAVIS", None), os.getenv("TRAVIS_JOB_ID", None), os.getenv("TRAVIS_BRANCH", None)]:
            env = os.environ.copy()
            env["PYTHONPATH"] = os.pathsep.join(sys.path)
            cmd = ["coveralls"]
            coveralls_retry = 5
            while subprocess.call(cmd, env=env) and coveralls_retry:
                coveralls_retry -= 1
                if coveralls_retry:
                    seconds = 10
                    print("coveralls was unsuccessful. sleeping for %s seconds before retrying." % seconds)
                    time.sleep(seconds)
                else:
                    print("coveralls failed.")

        os.chdir(owd)

        raise SystemExit(errno)

jwt_require = ["PyJWT", "cryptography"]

pki_require = ["certifi"]
if version_info < (3, 0):
    pki_require = pki_require + ["pyopenssl", "ndg-httpsclient"]

tests_require = ['coverage', 'beautifulsoup4', 'html5lib', 'coveralls'] + jwt_require
if version_info < (3, 3):
    tests_require = tests_require + ['mock==2.0.0', 'pbr<1.7.0']

setup(
    name = "django-allauth-adfs",
    version = "0.1.5",
    author = "gordon",
    author_email = "wgordonw1@gmail.com",
    description = "ADFS oAuth provider for django-allauth",
    url = "https://github.com/thenewguy/django-allauth-adfs",
    cmdclass={'test': RunTestsCommand},
    packages=find_packages(),
    extras_require={
        "jwt": jwt_require,
        "pki": pki_require,
    },
    install_requires=['django-allauth>=0.26.0', 'six'],
    tests_require=tests_require,
    classifiers = [
        'Programming Language :: Python',
        'Operating System :: OS Independent',
        'Framework :: Django',
    ],
)
