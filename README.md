Vircle Core integration/staging tree
=====================================

[![Build Status](https://travis-ci.org/vircle/vircle-core.svg?branch=master)](https://travis-ci.org/vircle/vircle-core)

https://vircle.io

What is Vircle?
----------------

An open source, decentralized privacy platform
built for global person to person eCommerce.

For more information, as well as an immediately useable, binary version of
the Vircle Core software, see https://vircle.io.


Getting Started
---------------

A new Vircle wallet will need an HD master key loaded and an initial account
derived before it will be functional.

The GUI programs will guide you through the initial setup.

It is recommended to use a mnemonic passphrase.
To generate a new passphrase see the mnemonic rpc command.
Loading the new mnemonic with the extkeyimportmaster command will setup the
master HD key and first account.

To create an initial new HD master key and account from random data, start
vircled or vircle-qt with the parameter: -createdefaultmasterkey.

Remember to backup your passphrase and/or wallet.dat file!

License
-------

Vircle Core is released under the terms of the MIT license. See [COPYING](COPYING) for more
information or see https://opensource.org/licenses/MIT.

Development Process
-------------------

The `master` branch is regularly built and tested, but is not guaranteed to be
completely stable. [Tags](https://github.com/vpubchain/vircle-core/tags) are created
regularly to indicate new official, stable release versions of Vircle Core.

The contribution workflow is described in [CONTRIBUTING.md](CONTRIBUTING.md)
and useful hints for developers can be found in [doc/developer-notes.md](doc/developer-notes.md).

Testing
-------

Testing and code review is the bottleneck for development; we get more pull
requests than we can review and test on short notice. Please be patient and help out by testing
other people's pull requests, and remember this is a security-critical project where any mistake might cost people
lots of money.

### Automated Testing

Developers are strongly encouraged to write [unit tests](src/test/README.md) for new code, and to
submit new unit tests for old code. Unit tests can be compiled and run
(assuming they weren't disabled in configure) with: `make check`. Further details on running
and extending unit tests can be found in [/src/test/README.md](/src/test/README.md).

There are also [regression and integration tests](/test), written
in Python, that are run automatically on the build server.
These tests can be run (if the [test dependencies](/test) are installed) with: `test/functional/test_runner.py`

The Travis CI system makes sure that every pull request is built for Windows, Linux, and macOS, and that unit/sanity tests are run automatically.

### Manual Quality Assurance (QA) Testing

Changes should be tested by somebody other than the developer who wrote the
code. This is especially important for large or high-risk changes. It is useful
to add a test plan to the pull request description if testing the changes is
not straightforward.

### Developer Rewards
Each person involved in the development of The Vircle-Core blockchain ecosystem technology 
will have the opportunity to share a token award of 6% of the total release proceeds.