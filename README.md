# password
## a command line password manager

This a personal password manager, written for me, that operates on the
command line. It stores and retrieves passwords and optional metadata
as well. By default, passwords are stored to `${HOME}/.passwords.db`
(you can see this with `password -h`, observing the default value for
the `-f` flag). This can be changed by passing an argument to the `-f`
flag.

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


## Example

For the sake of argument, let's assume you have three accounts:

* example.net with password "password1"
* example.com with password "password2"
* example.org with password "password3"

The example.com account additionally has three security questions:

* Q. "What is your name?" A. "Sir Lancelot of Camelot"
* Q. "What is your quest?" A. "To seek the Holy Grail"
* Q. "What is your favourite colour?" A. "blue"

Since you're using `password` for the first time, you can enter all
these passwords at once:

```
$ password -multi
Use an empty name to indicate that you are done.
Name: example.net
Password: 
Name: example.com
Password: 
Name: example.org
Password: 
Name: 
Database passphrase: 
$ 
```

If you list the accounts stored:

```
$ password -l    
Database passphrase: 
Names:
        example.com
        example.net
        example.org
```

You can enter the security questions for example.com:

```
$ password -s -m example.com
Database passphrase: 
Enter metadata; use an empty line to indicate that you are done.
key = value: What is your name? = Sir Lancelot of Camelot
key = value: What is your quest? = To seek the Holy Grail
key = value: What is your favourite colour? = blue
key = value: 
$
```

By default, `password` won't show metadata when retrieving a password:

```
$ password example.com
Database passphrase: 
Password: "password2"
$
```

You can show metadata with the `-m` flag:

```
$ password -m example.com
Database passphrase: 
Password: "password2"
What is your quest?="To seek the Holy Grail"
What is your favourite colour?="blue"
What is your name?="Sir Lancelot of Camelot"
```

Meanwhile, it looks like example.org has changed their privacy policy,
and you don't like the direction they're taking. So, you've deleted
your account there. Time to remove it from `password`:

```
$ password -r example.org
Database passphrase:
Done.
$
```

If you list your accounts again:

```
 $ password -l
Database passphrase: 
Names:
        example.com
        example.net
$
```

Some time passes, and you think you should change your master password.

```
$ password -c
Database passphrase: 
Changing password...
Database passphrase:
$
```

If you wanted to back up your password database, you can pass around
the binary file, or you can export to PEM.

```
$ password -export -
-----BEGIN PASSWORD STORE-----
z2rNMKINVV/8+hO3pxw9vAlHXieml/5zMt+lGnaQHmcU5cM/X9DmfBnj9Sk0hpsQ
V90j660VOBMuwTHijgkQ0PSqifxZtdRA/5D7mM9Q3j69V/uwbrb3I8akB0vb/Knl
SYI9bikTxnbe2sVb7Vw8Ta3E/Kh1chp8LVHbh6OI+ww/H8jV76MYmp4FW5wApp9y
0AaTa3dMC1O1NctBN6KrPuN0JG//P8fsyEDXwosd3eVqiLfj+tsNUX29rc7pc8yS
LhO248rP2Hv7jhX8Pl/0ynrANJkaVnz+4+pwFbUg2A2WYxv8MBQAZm1gdX2nHEuZ
tQv5gPlfjyPnt2iArgKoSC+07qQ7VSqrSib23tAA/pAQJWYXB8o9GE7B3diOHbvC
ir9ZDvO5P8WEkh5EA10HZjmqj38m1OWlO7bmhtVoDFfHRrpUxMWh+K3hnXnJjGOA
AwTgs8VkDccaOzEnbgDRhvlS3qcrcaGNge4kd65XlUoW2YvzoIoPcoAWX7jiBvpC
eA==
-----END PASSWORD STORE-----

$
```

Maybe you'd rather actually store it to a file, instead of printing to
standard output:

```
$ password -export passwords.pem
$ cat passwords.pem 
-----BEGIN PASSWORD STORE-----
z2rNMKINVV/8+hO3pxw9vAlHXieml/5zMt+lGnaQHmcU5cM/X9DmfBnj9Sk0hpsQ
V90j660VOBMuwTHijgkQ0PSqifxZtdRA/5D7mM9Q3j69V/uwbrb3I8akB0vb/Knl
SYI9bikTxnbe2sVb7Vw8Ta3E/Kh1chp8LVHbh6OI+ww/H8jV76MYmp4FW5wApp9y
0AaTa3dMC1O1NctBN6KrPuN0JG//P8fsyEDXwosd3eVqiLfj+tsNUX29rc7pc8yS
LhO248rP2Hv7jhX8Pl/0ynrANJkaVnz+4+pwFbUg2A2WYxv8MBQAZm1gdX2nHEuZ
tQv5gPlfjyPnt2iArgKoSC+07qQ7VSqrSib23tAA/pAQJWYXB8o9GE7B3diOHbvC
ir9ZDvO5P8WEkh5EA10HZjmqj38m1OWlO7bmhtVoDFfHRrpUxMWh+K3hnXnJjGOA
AwTgs8VkDccaOzEnbgDRhvlS3qcrcaGNge4kd65XlUoW2YvzoIoPcoAWX7jiBvpC
eA==
-----END PASSWORD STORE-----

$
```

Now, you want to import this on another machine:

```
$ password -import passwords.pem
$ password -l                   
Database passphrase: 
Names:
        example.com
        example.net
$
```

(The password for this example store is "password1", and you can
import it on your machine from PEM to see for yourself.)

One of your friends now has a hot startup at example.io, and you want
to add your account there:

```
 $ password -s example.io
Database passphrase: 
Password:
```

Time passes, and you get an email from example.com that they've had a
database breach, and your password is compromised. As a safety
measure, `password` won't let you just overwrite a password:

```
$ password -s example.com
Database passphrase: 
[!] entry exists, not forcing overwrite
$
```

You can tell `password` to overwrite the stored passphrase with the
`-o` flag:

```
 $ password -s -o example.com
Database passphrase: 
[!] *** warning: overwriting password
Password:
$
```

There's not much else to `password`.


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
* [apg](http://www.adel.nursat.kz/apg/) -- the automated password
  generator. It's in OpenBSD's packages, Ubuntu's repositories, and
  Homebrew (and possibly others that I didn't check). I use this for
  generating passwords.


## License

`password` is released under the ISC license.
