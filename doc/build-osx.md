Mac OS X Build Instructions and Notes
====================================
<<<<<<< HEAD
The commands in this guide should be executed in a Terminal application.
The built-in one is located in `/Applications/Utilities/Terminal.app`.
=======
This guide will show you how to build litecoind(headless client) for OS X.

Notes
-----

* Tested on OS X 10.7 through 10.10 on 64-bit Intel processors only.

* All of the commands should be executed in a Terminal application. The
built-in one is located in `/Applications/Utilities`.
>>>>>>> 0.10

Preparation
-----------
Install the OS X command line tools:

<<<<<<< HEAD
`xcode-select --install`
=======
You need to install Xcode with all the options checked so that the compiler
and everything is available in /usr not just /Developer. Xcode should be
available on your OS X installation media, but if not, you can get the
current version from https://developer.apple.com/xcode/. If you install
Xcode 4.3 or later, you'll need to install its command line tools. This can
be done in `Xcode > Preferences > Downloads > Components` and generally must
be re-done or updated every time Xcode is updated.

There's also an assumption that you already have `git` installed. If
not, it's the path of least resistance to install [Github for Mac](https://mac.github.com/)
(OS X 10.7+) or
[Git for OS X](https://code.google.com/p/git-osx-installer/). It is also
available via Homebrew.
>>>>>>> 0.10

When the popup appears, click `Install`.

Then install [Homebrew](https://brew.sh).

Dependencies
----------------------

    brew install automake berkeley-db4 libtool boost miniupnpc openssl pkg-config protobuf python3 qt libevent

See [dependencies.md](dependencies.md) for a complete overview.

If you want to build the disk image with `make deploy` (.dmg / optional), you need RSVG

    brew install librsvg

If you want to build with ZeroMQ support
    
    brew install zeromq

NOTE: Building with Qt4 is still supported, however, could result in a broken UI. Building with Qt5 is recommended.

Berkeley DB
-----------
It is recommended to use Berkeley DB 4.8. If you have to build it yourself,
you can use [the installation script included in contrib/](/contrib/install_db4.sh)
like so

```shell
./contrib/install_db4.sh .
```

<<<<<<< HEAD
from the root of the repository.

**Note**: You only need Berkeley DB if the wallet is enabled (see the section *Disable-Wallet mode* below).
=======
After exiting, you'll get a warning that the install is keg-only, which means it wasn't symlinked to `/usr/local`.  You don't need it to link it to build litecoin, but if you want to, here's how:
>>>>>>> 0.10

Build Litecoin Core
------------------------

1. Clone the litecoin source code and cd into `litecoin`

<<<<<<< HEAD
        git clone https://github.com/litecoin-project/litecoin
        cd litecoin

2.  Build litecoin-core:

    Configure and build the headless litecoin binaries as well as the GUI (if Qt is found).

    You can disable the GUI build by passing `--without-gui` to configure.
=======
### Building `litecoind`

1. Clone the GitHub tree to get the source code and go into the directory.

        git clone https://github.com/litecoin-project/litecoin.git
        cd litecoin

2.  Build litecoind:
>>>>>>> 0.10

        ./autogen.sh
        ./configure
        make

3.  It is recommended to build and run the unit tests:

        make check

<<<<<<< HEAD
4.  You can also create a .dmg that contains the .app bundle (optional):

        make deploy

5.  Installation into user directories (optional):
=======
4.  (Optional) You can also install litecoind to your path:
>>>>>>> 0.10

        make install

    or

<<<<<<< HEAD
        cd ~/litecoin/src
        cp litecoind /usr/local/bin/
        cp litecoin-cli /usr/local/bin/

Running
-------

Litecoin Core is now available at `./src/litecoind`

Before running, it's recommended you create an RPC configuration file.
=======
1. Make sure you installed everything through Homebrew mentioned above
2. Do a proper ./configure --with-gui=qt5 --enable-debug
3. In Qt Creator do "New Project" -> Import Project -> Import Existing Project
4. Enter "litecoin-qt" as project name, enter src/qt as location
5. Leave the file selection as it is
6. Confirm the "summary page"
7. In the "Projects" tab select "Manage Kits..."
8. Select the default "Desktop" kit and select "Clang (x86 64bit in /usr/bin)" as compiler
9. Select LLDB as debugger (you might need to set the path to your installtion)
10. Start debugging with Qt Creator

Creating a release build
------------------------
You can ignore this section if you are building `litecoind` for your own use.

litecoind/litecoin-cli binaries are not included in the Litecoin-Qt.app bundle.

If you are building `litecoind` or `Litecoin-Qt` for others, your build machine should be set up
as follows for maximum compatibility:
>>>>>>> 0.10

    echo -e "rpcuser=litecoinrpc\nrpcpassword=$(xxd -l 16 -p /dev/urandom)" > "/Users/${USER}/Library/Application Support/Litecoin/litecoin.conf"

    chmod 600 "/Users/${USER}/Library/Application Support/Litecoin/litecoin.conf"

<<<<<<< HEAD
The first time you run litecoind, it will start downloading the blockchain. This process could take several hours.
=======
Once dependencies are compiled, see release-process.md for how the Litecoin-Qt.app
bundle is packaged and signed to create the .dmg disk image that is distributed.
>>>>>>> 0.10

You can monitor the download process by looking at the debug.log file:

<<<<<<< HEAD
    tail -f $HOME/Library/Application\ Support/Litecoin/debug.log

Other commands:
-------

    ./src/litecoind -daemon # Starts the litecoin daemon.
    ./src/litecoin-cli --help # Outputs a list of command-line options.
    ./src/litecoin-cli help # Outputs a list of RPC commands when the daemon is running.
=======
It's now available at `./litecoind`, provided that you are still in the `src`
directory. We have to first create the RPC configuration file, though.

Run `./litecoind` to get the filename where it should be put, or just try these
commands:

    echo -e "rpcuser=litecoinrpc\nrpcpassword=$(xxd -l 16 -p /dev/urandom)" > "/Users/${USER}/Library/Application Support/Litecoin/litecoin.conf"
    chmod 600 "/Users/${USER}/Library/Application Support/Litecoin/litecoin.conf"
>>>>>>> 0.10

Using Qt Creator as IDE
------------------------
You can use Qt Creator as an IDE, for litecoin development.
Download and install the community edition of [Qt Creator](https://www.qt.io/download/).
Uncheck everything except Qt Creator during the installation process.

<<<<<<< HEAD
1. Make sure you installed everything through Homebrew mentioned above
2. Do a proper ./configure --enable-debug
3. In Qt Creator do "New Project" -> Import Project -> Import Existing Project
4. Enter "litecoin-qt" as project name, enter src/qt as location
5. Leave the file selection as it is
6. Confirm the "summary page"
7. In the "Projects" tab select "Manage Kits..."
8. Select the default "Desktop" kit and select "Clang (x86 64bit in /usr/bin)" as compiler
9. Select LLDB as debugger (you might need to set the path to your installation)
10. Start debugging with Qt Creator
=======
    tail -f $HOME/Library/Application\ Support/Litecoin/debug.log
>>>>>>> 0.10

Notes
-----

* Tested on OS X 10.8 through 10.13 on 64-bit Intel processors only.

<<<<<<< HEAD
* Building with downloaded Qt binaries is not officially supported. See the notes in [#7714](https://github.com/bitcoin/bitcoin/issues/7714)
=======
    ./litecoind -daemon # to start the litecoin daemon.
    ./litecoin-cli --help  # for a list of command-line options.
    ./litecoin-cli help    # When the daemon is running, to get a list of RPC commands
>>>>>>> 0.10
