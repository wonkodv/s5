# User guide

This File gives instructions to the end user how client and server are
installed and used correctly.
For shell commands, optional parameters are enclosed in square brackets, and
variable parts are written in upper case.

## Securing the System

As with every software solution to secure information, every protection can be
circumvented if used on an insecure machine. Malicious programs can inspect the
memory of the **S5** program, log keys when the user enters passwords, include
malware in items to infect other devices etc. To protect private data, a virus
scanner should be installed and the device protected from access by
others physically.

## Installation

The **S5** is implemented using Python 3.4 with the additional package `pycrypto`
and, only for testing, `coverage`. Client and server software were tested to
work with the following Linux distributions:

* Arch (updated in December 2014)
* Ubuntu 14.04
* Debian 7.7 (wheezy) with Python packages from `testing`

 The `pycrypto` package can be installed from the Python Package Index using `pip`, or with
`apt-get install python3-crypto` on Debian and Ubuntu and `pacman -S
python-crypto` on Arch.


The distributed **S5** tar ball should contain the following files and directories:

* `s5`: The Python package that contains the Python code of client and server.
* `test.py`: A Python script that can be executed to run all tests and create a
  coverage report.
* `Makefile`: A collection of small tools.
* `setup.py`: The installation script.

To execute client or server, Python has to be called in the correct version,
with a variable pointing at the location of the code and the module to execute.
For example the client is started with

    PYTHONPATH=/path/to/implementation python3.4 -m s5.client

To install the package the install script can be executed or `pip` can be used.
Each of the following commands will install the s5 package into the default
python site directory and the two scripts `s5` (the client) and `s5server` (the
server) into the shell's search path:

    pip install /path/to/implementation
    pip install https://github.com/wonkodv/s5
    python setup.py install

Read the help from the commands `pip install --help` or `python
setup.py --help` for more options.


## Configuration

Both, client and server, can be configured with configuration files. They both use
a default file, which is shipped with the code (`s5/server/defaults.ini` and
`s5/client/defaults.ini`), that contains all options, with comments explaining
their meaning. The default files should not be modified by the user and can
change with future versions of the software.

To configure the client or server differently, the user can create a second
configuration file that overwrites options from the first. It must use the same
syntax and option names, but does not have to contain all options. The user
defined files are named `config.ini` and searched for in the data directories of
client and server respectively.

The syntax of the configuration files is similar to the common `.ini` files on
windows^[The files are parsed with `configparser`, without interpolation
(<https://docs.python.org/3/library/configparser.html>).], with sections in
square brackets and option value pairs separated by equal signs. Long values can
be split into multiple lines if they are all indented.

    [Section]
    Option = Key
    Option 2 = Long
        Value That contains
        multiple line breaks
    # Comment Line

    [Next Section]
    ...

The configuration files mainly define which cryptographic methods to use, but also
which networks the server listens on, or the email address that the client
publishes in share groups.


## Server

For all commands, the server needs to be passed a parameter `--data` with a path
to the directory where all server data is stored.

### Initialization

To create the data directory and populate it with necessary files and
subdirectories, it must not already exist. Using the `s5server` script, the
command to execute is:

*   `s5server --data DATA init`

After a software upgrade, the data directory might need to be modified, this can
be done with:

*    `s5server --data DATA upgrade`

### Starting and Stopping the Server

The server will accept TCP connections with the following command:

*    `s5server --data DATA serve [--address ADDRESS] [--port PORT]
     [--ipv6]`

In the `Network` section of the configuration file, the address, port and IP
version can be set.
Those values will be overwritten by arguments passed on the
command line. By default, the IP version 4 is used, listening on `localhost` at
port `8091`. To listen on all network interfaces, `0.0.0.0` can be passed as
address. The port must be unique on the system and greater than 1023 if not
running as root.  By passing `--ipv6` or setting it in the
configuration file, only IPv6 will be used.

The server can be stopped by
executing

*   `s5server --data DATA kill`

or by pressing CTRL-C or sending it a `SIGINT` signal.  It will wait for
connected clients to finish and then quit.

### User Management

The server identifies clients by the public key, that they connect with. If the
user is not a registered user, nor member of any share group, he is not allowed
to do anything, except sending tokens.
To become a registered user, the server operator has to create a
token for the user, which the user has to submit using his user key. The user's
key will then be tied to that account. A token is created with:

* `s5server --data DATA create-token USER`

The value passed as `USER` is only seen by the server operator. It could, for
example, be an email address.

The token must be sent to the client via a secure channel, or via two separate
channels, e.g. the first half via email and the second via instant messaging.
The token can only be used once.

### Fingerprint

Clients verify the server by the server's key fingerprint. The method with
which that fingerprint is computed can be defined by the client. Therefore, there
is no one fingerprint for a server key, instead it depends on the hash method
used.
With

* `s5server --data DATA fingerprint [HASH]`

the fingerprint of the server key is printed using `HASH` or, if no method is
passed, all hash methods known to the server. The client uses `sha384` by
default.

### Configuration

A `config.ini` file in the data directory can be used to override default
settings. It must have the same syntax as `s5/server/defaults.ini` in the
code directory, but should only include those options that differ. Usually, the network
address and port should be changed.


## Client

The client has a total of 33 commands, grouped into 7 categories. Each command
accepts a set of arguments and options, and there are some global options that
are valid for every command.

Adding `--help` or `-h` to any command, will print a help message that gives
details about allowed and expected parameters for that command.

Commands that work with items use the following in their parameter description:

* `PATH` is a string containing multiple names, joined by slashes.
* `ID` must be a valid item id (32 hexadecimal digits).
* `ITEM` can be a path, item id or partial item id. A partial item id is the
     beginning of an item id of a local item. It must be long enough to be
     unique.


### Global Options
* `s5 --data DIRECTORY ...`

    The client will store all data in `~/.s5` per default, or in `DIRECTORY` if given.
* `S5_PASSWORD=PASSWORD s5 ...`

    If the client needs to access the user key, the password, that the key is
    encrypted with, must be entered. This can be avoided by passing the password
    as environment variable `S5_PASSWORD`. This is preferable to using an
    argument since (on Linux) every OS user can read the arguments of all
    running processes.  To avoid the password showing up in a shell's history
    file, it can be set as a variable with `read`. In Bash, `read` will not
    print the input characters with the `-s` flag.

		read -s S5_PASSWORD
		# enter the password
		export S5_PASSWORD

* `s5 --log-level LEVEL ..`

    `LEVEL` can be any of `DEBUG`, `INFO`, `WARNING` or `ERROR` with `WARNING`
    being the default. This influences which log messages are printed to
    `stderr`.

* `s5 --batch ... `

    This disables any input requests, for example asking the user for his
    password. If the value is not specified otherwise (per option, or password
    variable), the operation will fail. To some assurance questions, `YES` will
    be assumed.

* `s5 --stack-trace ...`

    By default, only the message of an error is printed. With this option
    enabled, the complete stack trace will be printed in Python's default
    format.

All the global options can be included in the `s5` script to activate them
permanently.

### Core Commands

Same as the server, the client has to be initialized before first use:


*    `s5 core init [--key KEY]`

    With `s5 core init` a new user key will be generated by default. By
    specifying a file that contains an exported key as `KEY`, you will be asked for the
    password to decrypt that exported key and it will be set up as your user
    key.  Servers identify all clients with the same user key as
    the same user, which allows users to access items from several devices.

*    `s5 core upgrade`

    After updating the software to a newer version, the data directory may need
    to be upgraded.

*    `s5 core export-key`

    Exports the user key. It will be encrypted with a generated password and
    stored in a file, filename and password are printed to standard out.
     Copy that file to other devices and run `s5 core init
    --key KEY` there.

*  `s5 core set-root-id ID`

    When using the same key on more than one device, you can set up the same item as
    root of the catalog on all devices. Thereby, the complete item tree can be
    accessed on all devices. On light weight devices like smart
    phones, it might be better to have a different item as root, possibly a sub
    item of another device's catalog, that contains only those items that you
    want to have on that device.


		## On device A
		# synchronize the complete item catalog to a server
		s5 sync push --server SERVER /
		# get the item ID of the root
		s5 item inspect /
		# Export the Key
		s5 core export-key

		# copy the key to device B
		scp A:/tmp/...S5Key B:/tmp/S5Key

		## on device B:
		# Init and import the user key
		s5 init --key /tmp/S5Key
		# Set the root item id to the same as on Client A
		s5 set-root-id ROOTID
		# add the same server
		s5 server add SERVER ...
		# pull the complete catalog
		s5 sync pull --recursive --server SERVER /

		# securely delete the .S5Key files on both devices

* ` s5 core list-crypto`

    Prints the list of all available cryptographic algorithms, using the names
    that can be used in the configuration file.

### Item

Items that are in the local repository can be modified with these
commands:

* `s5 item new [-f] [-p] [-t TYPE] PATH`

    Creates a new item and links it at `PATH`.

    If not all path components except the last already exist,
    `-p` or `--parents` must be passed to create them as well,
    otherwise the operation will fail.

    If an item already exists at that path and `-f` or `--force` argument is given,
    it will be unlinked and replaced by the new one, otherwise the operation fails.

    The new item will be a map by default, but another type can be specified with
    `--type` or `-t`.

		s5 item new shared
		s5 item new shared/withBob/pictures --parents

* `s5 item write [-f] [-p] [-t TYPE] ITEM`

    Reads from standard in and writes the content of an item.

    If `ITEM` is a path, a new item is created and put at that path. If path
    components do not yet exist, these are created if `-p` or `--parents` is
    passed.
    If there already exists an item at that path, or if `ITEM` is a (partial)
    item id, `--force` or `-f` must be passed to overwrite that item's content,
    otherwise an error is returned.

    The default type for the created item is `urn:x-s5:file`, but can be
    overwritten with `--type` or `-t`.

		s5 item write photos/surfing-2014/pic01 \
			-t "urn:x-s5:file(image/jpeg)" \
			 < /mnt/sdcard/DCIM/IMG_10020056.jpg

* `s5 item edit [-i] [-t TYPE] [-f] [-p] [-j] [-e EDITOR] ITEM`

    Edits the content of `ITEM`. This is useful to edit or view the text of items
    with a text editor like `vim`, but can be used to modify items of any type,
    for example to modify map items by hand, but also to open spreadsheets with
    `libreoffice` or similar.

    The item content is written
    to a temporary file and that file is edited with `EDITOR` (defaulting to
    environment variable `EDITOR` and, as last resort, `vim`). After the editor
    closes, the file content is stored in the item and the temporary file
    removed.

    Differing from `s5 item write` existing items are expected. If the item does
    not yet exist, it is only created if `--force` or `-f` is passed. In that
    case, missing path components are created if `-p` or `--parents` is passed.
    The default type for a new item is `urn:x-s5:file`, but can be chosen with
    `-t` or `--type`.

    The `--json` or `-j` option can be used to edit a formatted version of the
    content of items that contain JSON data.
    The formatted text represents the same object, but is more human readable.

    To only view the content and not modify it, `-i` or `--ignore-changes` can
    be passed. Even if the editor modifies the file, the item content will not
    be modified. The file mode will be changed to read only (`0o400`) allowing
    the editor to warn about accidental modifications.

		s5 item edit recipes/cake

* `s5 item open ITEM`

    Opens the item `ITEM` in its default application, for example, to view pictures or edit
    documents.

    This is currently a shorthand for: `s5 item edit -e "xdg-open" ITEM`. This
    works only on some Linux and Unix systems and decides which application to
    use based on the content, ignoring the item type (and for file items,
    the possibly stored mime type). This works well for images, documents, etc.

		s5 item open photos/surfing-2014/pic01

* `s5 item link [-f] [-p] ITEM PATH`

    Makes the item `ITEM` available under `PATH`.
    If the target item does not yet exist locally, `ITEM` must be a full item
    id. If the target already exists locally, `ITEM` can be a (partial) item id
    or a path to an item.

    Similar to `s5 item new`, `-f` or `--force` will unlink an existing item at `PATH` and
    `--parents` will create missing parents in `PATH`.

		s5 item link photos/surfing-2014 shared/withBob/surfing-2014

* `s5 item unlink PATH`

    Removes the reference to an item from its parent item. This does not delete
    the item, only severs access using that path. If the item is linked to in
    another path, that is not touched. Otherwise the item can only be referenced
    by its id.

		s5 item unlink photos/surfing-2014/pic07

* `s5 item dump ITEM`

    Writes the content of `ITEM` to `stdout`.

		s5 item dump photos/surfing-2014/pic01 > ~/pictures/bob.jpg

To inspect an item or a tree of items the following commands can be used:

* `s5 item inspect [--meta] [--hex] [--json] [--dump] [--sync] [--share] ITEM`

    Gets information about an item.

    `--meta` shows meta data like encryption algorithm, size of compressed and
    encrypted content, etc.

    `--hex` prints a hexadecimal representation of the content, similar as
    piping it to `xxd`.

    `--json` pretty prints the content of items containing only JSON data.

    `--dump` same as `s5 item dump`.

    `--sync` shows information about the latest synchronization with all servers.

    `--share` shows information about groups, this item is shared with.

    Multiple options can be combined, if none is given, `--meta` is the default.

		s5 item inspect --meta --json shared/withBob

* `s5 item tree [--depth DEPTH] [--id] [--meta] [--text] [--hex]
     [--json] [--sync] [--share] [ITEM]`

    Prints a tree that is rooted in `ITEM` or the catalog root item.

    If an item is referenced by id in another, but no item with that id exists
    locally, that item is marked with `not local` and no further information
    is printed.

    If an item has a type, for which no accessor is installed, that item is
    marked as `unsupported type` and no children are displayed, even if that
    item has children.

    An item that has no content yet (e.g. created with `s5 item new` and never
    written to) is marked with `empty`

    `--depth` specifies the maximum depth of the printed tree.
    If an item has children beyond the
    depth, this is indicated by two lines with dots.

    The following modifiers add lines of information after an items name, before
    its children.

    `--id` prints the id of an item.

    `--text` UTF-8 decode the content and print the first ten lines, wrapping lines
    that are longer than the space in the tree.

    `--share` prints the server name, group name and group id for every server
    the item is shared on.

    The options `--meta`, `--hex`, `--json` and `--sync` behave
    similar to `s5 item inspect`.

		s5 item tree shared --id
		shared
		 │    0D9D0BFB2736811AF85EBF8F4353765D
		 ├──withBob
		 │   │    E5F5592DAE555FFE67CD12937FC4793E
		 │   └──surfing-2014
		 │       │    D17DA148F4BA381B3A1FF9C8F22AA7AF
		 │       ├──pic01
		 │       │        7903E993E15CC3D4CB5331500C834C66
		 │       └──pic02
		 │                E9BDDB5753378D9A1AB4B800861E0BFA
		 └──withCharlie
			 │    FE4DD2D77E8554A879AFE3E74A8937B3
			 └──surfing-2014
				 │    D17DA148F4BA381B3A1FF9C8F22AA7AF
				 ├──pic01
				 │        7903E993E15CC3D4CB5331500C834C66
				 └──pic02
						  E9BDDB5753378D9A1AB4B800861E0BFA

* `s5 item find ID`

    Finds the path(s) where an item with (the partial) `ID` is linked

		s5 item find 7903
		shared/withBob/surfing-2014/pic01 7903E993E15CC3D4CB5331500C834C66
		shared/withCharlie/surfing-2014/pic01 7903E993E15CC3D4CB5331500C834C66

* `s5 item gc`

    Garbage Collect: This will delete all items locally, which are not reachable
    via the catalog.

### Server

Servers are given a name so they can be easily used in other commands. This name
is specified when the server is added.
These commands are used to manage servers:

* `s5 server add NAME HOST PORT [-m FPM] [-p FP] [-f]`

    Adds a server to the list of known servers.
    `NAME` is the name by which the server can be referred
    to in other commands. `HOST` can be an IP (v4 or v6) address, a computer name or a
    domain name. `PORT` is the TCP port that the server accepts connections on.

    A connection will be made to the server, in which the server will send his
    public key, of which a fingerprint will be calculated. The method can be
    selected with `-m` or `--fingerprint-method`, otherwise the method selected
    in the configuration file will be used, defaulting to `sha384`.

    If `-p` or `--fingerprint` is passed, the passed value must match the
    fingerprint over the server's key. Without that option, the user is asked to
    verify the correctness.

    To overwrite an existing server with the same name, pass `-f` or `--force`.
    This is useful if the server key, address or port changed.

    If the fingerprint is correct, it is stored together with the name, host and
    port and checked at every connection.

* `s5 server token SERVER TOKEN`

    Sends a token to the server.

    This can have different effects on different server implementations.
    On the standard server, only registered users can create share groups. The
    server operator can create a token for you to submit with this
    command. This makes you a registered user on that server and allows you to
    create share groups.

* `s5 server list`

    Prints a list of all server names, ports and hosts.

* `s5 server ping SERVER`

    Connects to the server, sends a ping, waits for the reply and prints the round
    trip time, as well as the total time for establishing a secure connection.
    Due to the dynamic runtime behaviour of Python, the measured values will be
    rather high and scatter considerably.

### Sync

* `s5 sync pull -s SERVER [-r] [-d DEPTH] [-f] ITEM`

    Pulls the newest version of `ITEM` from the server `SERVER`.

    If `--recursive` or `-r` is given, the same is done for every child item recursively.

    If a depth is specified with `-d` or `--depth`, this implies `-r` but the
    recursion dept is limited.

    If an item was modified since it was last synchronized, it will not be
    updated, unless `--force` or `-f` is passed.

* `s5 sync pull-version -s SERVER -v VERSION ITEM`

    Pulls the version `VERSION`  of item `ITEM` from the server `SERVER`,
    overwriting any local changes.


* `s5 sync push -s SERVER [-a] [-n] ITEM`

    For the tree of items, that is rooted in `ITEM`, submits changes in items
    that were synchronized with the server before and does the same for their
    children.

    With `-a` or `--add-unsynced`, changes in all items in the tree will be
    pushed.

    With the `-n` or `--dont-add-children` option, only changes in items that
    were synchronized before are pushed.

* Conflict resolution:

    If an item is changed, both on the server and locally, the s5 client can not
    resolve the conflict, but a combination of commands can be used to do so by hand:

    1. Export the local item content using either

        * `s5 item dump ITEM > TEMPFILE` for arbitrary items, or
        * `s5 item inspect --json ITEM > TEMPFILE` for items that contain JSON
             data.

    2. Get the server version of the item with :
        * `s5 sync pull -f ITEM`

    3. Merge the two versions of the item by opening the temporary file and the
        item in two instances of the corresponding program and modifying the
        item content by hand.
        * `xdg-open TEMPFILE &`
        * `item open ITEM`

        There are tools that help merging text in which only some lines differ, like
        source code, configuration files and formatted JSON data, for example
        with `vimdiff`:
        * `s5 item edit --json ITEM --editor "vimdiff TEMPFILE"`

    4. Overwrite and delete the temporary file (it contained unencrypted
    content):
        * `shred -u -z TEMPFILE`
    4. Now the local changes are based on the version, that is the newest on the
    server, and the item is no longer in conflict. The next `s5 item push` will
    be successful.

		s5 sync push shared  # fails because of a conflict in item A09C...
		s5 item inspect --json A09C > /tmp/A09CDump
		s5 sync pull -s Daves-server -f A09C
		s5 edit --json --editor "vimdiff /tmp/A09CDump " A09C
		s5 sync push shared # succeeds

### Share


* `s5 share list [-s SERVER] [--name NAME]`

    Lists all share groups that the user is a member of on all known servers.

    With `--server`, only groups on `SERVER` will be listed.

    Only groups with the given name will be listed with the `--name` parameter.

* `s5 share new -s SERVER NAME`

    Creates a new share group on `SERVER` with `NAME`. You will be added to the
    share group
    with all permissions and become the owner. There can only be one group with
    the same name per owner.

* `s5 share add-user -s SERVER [--temp-key] [--from-share FROM_SHARE]
    GROUP USER PERMISSIONS+`

    This command will add a user to a group on `SERVER`.

    `GROUP` must be the id or name of a group, that you are the owner of.

    `USER` should be the email address of the added member.

    `PERMISSIONS+` defines the permissions that the user will have.
        It can be one of

    * `NONE`
    * `ALL`

    or a combination of:

    * `WRITE_ITEMS`
    * `READ_ITEMS`
    * `ADD_ITEMS`
    * `REMOVE_ITEMS`
    * `LIST_MEMBERS`

    To add the user, his public key is needed.  If you and the user are both
    members of another group on the server, the key he has in that group can be used by
    specifying the id or name of that other group with `--from-share`. You
    should only do this, if you trust the owner of that group to store the correct
    key. This command is
    intended to create a group, that is a superset of other groups, in order to solve a
    share group inheritance conflict. In
    such a case, the new member already has links to the items that he can access
    with the new membership.

    In all other cases specify `--temp-key`. A temporary key will be generated and
    registered on the server as the new group member's key.  A `.S5Member` file
    will be created which contains the key, the address and the fingerprint of the
    server, the names and item ids of the roots of the item trees which are
    shared with the group, and the id of the group. The content of that file is
    encrypted with a generated password. The path to the file and password will
    be displayed.

    The user can replace the temporary key with his own using `s5 share
    become-member` with the file and the password.

    The file should be submitted to the user using a channel like email, instant
    messaging or similar, the password through a different one like telephone,
    SMS etc. If both are sent
    via email for example, your email provider, his email provider and a number
    of other parties which can read the email would be able to make themselves
    member of the share group.

		s5 share add-user -s daves-server --temp-key knitting-club charlie@example.com all
		...
		File: /tmp/tmpjligysgz.S5Member
		Password: 1nbpdS8o+W

* `s5 share become-member PATH IMPORT-PASSWORD ITEM`

    When someone added you to a share group on a server and sends you a
    `.S5Member` file, this command replaces the temporary key he created for you with
    your own, so you become a member of that group.

    `PATH` must point to the `.S5Member` file.

    `IMPORT-PASSWORD` is the password you were sent.

    `ITEM` must be an (empty) item in which all items that are shared with the
    group, will be linked. They will only be linked, not pulled from the server.

    If you have not yet added the server that the group is on, you will be asked
    for a name for that server and it will be added.
    You will also be asked for an email address by which other group members can
    identify you.

    After that, you can pull the items, (optionally limiting the depth) from the
    server.

		s5 item new shared/knitting-club
		s5 share become-member /tmp/tmpjligysgz.S5Member 1nbpdS8o+W shared/knitting-club
		Name for server s5.dave.example.org:8091: daves-server
		Your Email Address in Shares: charlie@example.com
		s5 sync pull -s daves-server shared/knitting-club -d 1

* `s5 share change-user-permissions -s SERVER GROUP USER PERMISSIONS+`

    Changes the permissions of a user in a group on a server.
    The parameters take the same values as for `s5 share add-user`.

* `s5 share add-item -s SERVER [-n] [-f] GROUP ITEM`

    This will add `ITEM` and all its child items to the group `GROUP` on the
    server. This implies pushing current changes (`s5 item push`).

    On one server, an item can only belong to one group. If an item is already
    shared, it is not removed from the old group and added to the new group
    unless `--force` or `-f` is passed.

    With `-n` or `--non-recursive` only the item itself will be shared, not its
    children.

### Files

To add directories and files to the item catalog, use:

*   `s5 files to-catalog [-u] [-p] ITEMPATH FILEPATH`

    If `FILEPATH` points at a file, a `FILE` item will be created at `ITEMPATH`,
    using the mime type that is guessed by the files extension, and the file
    content is stored in the item.
    If `FILEPATH` points at a directory, a `MAP` item will be created and the
    procedure repeated for all child files and directories, recursively.

    If `ITEMPATH` points to an existing item, this will cause an error, unless
    `-u` or `--update` is passed, which will lead to the item tree being
    updated, except for items that have newer modification times than the
    corresponding files. If a file or directory is deleted, the corresponding
    item will also be unlinked.

    With `-p` or `--parents`, missing items in `ITEMPATH` will be created.

### Configuration

The client can be configured in the same way as the server. The default
configuration file is shipped with the code in `s5/client/defaults.ini`,
 the user defined one is searched for in the data directory `DATA/config.ini`.

A recommended setting is `Email` in the `User` section. If not set, you will be
prompted to enter an address every time you create a share group or become
member of one.
