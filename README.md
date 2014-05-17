# password
## a command line password manager

This a personal password manager, written for me, that operates on the
command line. It stores and retrieves passwords and optional metadata
as well.

## Usage

To add a new password (password set):

```
password -s label
```

To retrieve the password for *label*:

```
password label
```

To change the password for *label* (password set overwriting):

```
password -s -o label
```

To remove the password for *label* (password remove):

```
password -r label
```

To change the master password for the password store:

```
password -c
```

To add metadata to *label* (password store metadata):

```
password -s -m label
```

To view metadata when retrieving the password for *label* (password metadata):

```
password -m label
```

To enter multiple labels and passwords in the same session:

```
password -multi
```

Both entering metadata and multiple labels/passwords will stop when
the first empty line is entered.


## Import / export

The password store can be imported from PEM or exported to PEM. Pass
either "-export" or "-import", and provide the source (when importing)
or destination (when exporting) file as the only argument. If "-" is
used as a filename, `password` will use either standard input or
standard output, as appropriate. This might be useful, for example, in
emailing the file to yourself or storing a printed backup.


## The password store:

The password are stored internally using a Go map; when dumped to
disk, it is first encoded to JSON, then encrypted using NaCl's
secretbox. The key for NaCl is derived using Scrypt (N=32768, r=8,
p=4) with a 32-byte salt that is randomly generated each time the
file is saved. The salt is stored as the first 32 bytes of the file.

I've taken care to attempt zeroing memory and passphrases where I can,
but there are no guarantees this is effective.

## See also

* [OTPC](https://github.com/kisom/otpc) -- a one-time password /
  two-factor command line client.


## License

`password` is released under the ISC license.
