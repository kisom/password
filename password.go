// password is a command line password manager built to my specifications.
package main

import (
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gokyle/readpass"
)

const timeFormat = "2006-01-2 15:04 MST"
const version = 1

// A Record contains an entry for a password. The timestamp is updated
// on any modification to the record (password or metadata
// changes). Metadata is stored as a byte slice to allow for zeroising
// when tearing down the record.
type Record struct {
	Name      string
	Timestamp int64
	Password  []byte
	Metadata  map[string][]byte
}

// Zero ensures that a record's entries are zeroised in memory. See
// the comment on zero in crypto.go for a longer discussion on this
// topic.
func (r *Record) Zero() {
	if r == nil {
		return
	}

	zero(r.Password)
	for k := range r.Metadata {
		zero(r.Metadata[k])
	}
}

// Display prints out the record. clipExport changes the output format
// of the record: only the password (sans trailing newline).
func (r *Record) Display(showMetadata, clipExport bool) {
	if !clipExport {
		fmt.Printf("Password: %s\n", r.Password)
	} else {
		fmt.Printf("%s", r.Password)
		return
	}
	if showMetadata {
		fmt.Printf("Timestamp: %d (%s)", r.Timestamp,
			time.Unix(r.Timestamp, 0).Format(timeFormat))
		for k, v := range r.Metadata {
			fmt.Printf("%s=%q\n", k, v)
		}
	}
}

func errorf(m string, args ...interface{}) {
	m = "[!] " + m
	if m[len(m)-1] != '\n' {
		m += "\n"
	}
	fmt.Fprintf(os.Stderr, m, args...)
}

// Passwords contains the in-memory representation of the password
// store. Version contains the password store format version (not the
// program version). Timestamp is updated when the password store is
// being written to disk.
type Passwords struct {
	Version   int
	Timestamp int64
	Store     map[string]*Record
}

// Zero attempts to zeroise each record in the store. See the previous
// discussions on the subject.
func (p Passwords) Zero() {
	for k := range p.Store {
		p.Store[k].Zero()
	}
}

// openFile decrypts and parses the password store from disk. The
// actual decryption is handled by functions defined in crypto.go. It
// will upgrade old password stores as required.
func openFile(fileName string) Passwords {
	fileData, err := decryptFile(fileName)
	if err != nil {
		errorf("Failed to open password file: %v", err)
		os.Exit(1)
	}

	var passwords Passwords
	err = json.Unmarshal(fileData, &passwords)
	if err != nil || passwords.Version != version {
		passwords, err = migrateStore(fileData)
		if err != nil {
			errorf("Failed to open store: %v\n", err)
			os.Exit(1)
		}
		saveFile(fileName, passwords)
	}
	if err != nil {
		errorf("Failed to open password file: %v", err)
		os.Exit(1)
	}
	return passwords
}

var migrations = map[int]func([]byte) (Password, error){}

// migrateStore brings old stores to the current format. This isn't
// particularly efficient, as the file is parsed twice more here
// (using the decrypted data): once to retrieve the version, and once
// to actually parse the store appropriately.
//
// TODO(kyle): do this in staged upgrades. That is, ensure the upgrade
// process goes from version, version+1...current version.
func migrateStore(data []byte) (Passwords, error) {
	var versioned = struct {
		Version int
	}{}

	err := json.Unmarshal(data, &versioned)
	if err != nil {
		return Passwords{}, err

	}
	switch v := versioned.Version; v {
	// If no version is present, the Version field will be
	// zero. Every format since v1 has included an integer
	// version field, so this is an accurate fallback.
	case 0:
		var old map[string]*Record
		err = json.Unmarshal(data, &old)
		if err != nil {
			errorf("Failed to open password file: %v", err)
			os.Exit(1)
		}
		for k := range old {
			if old[k].Timestamp == 0 {
				old[k].Timestamp = time.Now().Unix()
			}
		}

		fmt.Printf("Migrating from version 0 to version %d.\n", version)
		passwords.Version = version
		passwords.Timestamp = time.Now().Unix()
		passwords.Store = old
	default:
		versionMigrator, ok := migrations[versioned.Version]
		if !ok {
			err = fmt.Errorf("invalid password store")
			return Passwords{}, err
		}
		return versionMigrator(data)
	}
}

// saveFile serialises and encrypts the password store, using the
// crypto functions in crypto.go.
func saveFile(fileName string, passwords Passwords) {
	encoded, err := json.Marshal(passwords)
	if err != nil {
		errorf("Failed to serialise password store: %v", err)
		os.Exit(1)
	}

	err = encryptFile(fileName, encoded)
	zero(encoded)
	if err != nil {
		errorf("%v", err)
		os.Exit(1)
	}
}

/*
The commands in password are implemented as functions that cover the entire scope of the command. That is, each command opens the file and decrypts the contents as needed, and encrypts / saves the file as needed.

TODO(kyle): improve command handling such than an interactive mode might be enabled.
*/

// retrieveRecord looks up a record, displaying it appropriately.
func retrieveRecord(fileName, name string, showMetadata, clipExport bool) {
	passwords := openFile(fileName)
	defer passwords.Zero()
	rec, ok := passwords.Store[name]
	if !ok {
		errorf("entry not found")
		os.Exit(1)
	}
	rec.Display(showMetadata, clipExport)
}

// listRecords displays a list of all the names of passwords stored in
// this store.
func listRecords(fileName string) {
	passwords := openFile(fileName)
	defer passwords.Zero()

	if len(passwords.Store) == 0 {
		fmt.Printf("no passwords")
		return
	}

	var names = make([]string, 0, len(passwords.Store))
	fmt.Println("Names:")
	for k := range passwords.Store {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, name := range names {
		fmt.Printf("\t%s\n", name)
	}
}

// removeRecord deletes the named record from the store.
func removeRecord(fileName, name string) {
	passwords := openFile(fileName)
	defer passwords.Zero()

	delete(passwords.Store, name)
	saveFile(fileName, passwords)
	fmt.Println("Done.")
}

// removeMeta deletes metadata from the named record.
func removeMeta(fileName, name string) {
	passwords := openFile(fileName)
	defer passwords.Zero()

	rec, ok := passwords.Store[name]
	if !ok || rec.Metadata == nil {
		errorf("Nothing stored under the label %s", name)
		return
	}

	var keys = make([]string, 0, len(rec.Metadata))
	for k := range rec.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println("Keys:")
	for i := range keys {
		fmt.Printf("\t%s\n", keys[i])
	}
	for {
		key, err := readpass.DefaultPasswordPrompt("Remove key: ")
		if err != nil {
			errorf("Failed to read key: %v", err)
			continue
		} else if key == "" {
			break
		}
		delete(rec.Metadata, key)
		fmt.Println("Deleted key", key)
	}
	rec.Timestamp = time.Now().Unix()
	saveFile(fileName, passwords)
}

// storeRecord adds a new password under the named record. If the
// record exists, it must be explicitly overwritten. If the named
// record does not exist, a new one is created. If the password store
// doesn't exist, a new password store will be initialised.
func storeRecord(fileName, name string, overWrite bool) {
	var passwords = Passwords{}
	defer passwords.Zero()

	if _, err := os.Stat(fileName); err != nil && !os.IsNotExist(err) {
		errorf("Failed to open password store: %v", err)
		os.Exit(1)
	} else if err == nil {
		passwords = openFile(fileName)
	}

	rec, ok := passwords.Store[name]
	if ok {
		if !overWrite {
			errorf("entry exists, not forcing overwrite")
			os.Exit(1)
		} else {
			errorf("*** warning: overwriting password")
		}
	} else {
		rec = &Record{Name: name}
		passwords.Store[name] = rec
	}

	password, err := readpass.PasswordPromptBytes("Password: ")
	if err != nil {
		errorf("%v", err)
		os.Exit(1)
	} else if len(password) == 0 {
		errorf("no password entered")
		os.Exit(1)
	}
	defer zero(password)
	rec.Password = password
	rec.Timestamp = time.Now().Unix()

	saveFile(fileName, passwords)
}

// storeMany allows entering multiple name/password pairs to
// facilitate adding multiple labels (e.g. for a new password
// store). The same notes regarding storeRecord apply here.
func storeMany(fileName string, overWrite bool) {
	var passwords = Passwords{}
	defer passwords.Zero()

	if _, err := os.Stat(fileName); err != nil && !os.IsNotExist(err) {
		errorf("Failed to open password store: %v", err)
		os.Exit(1)
	} else if err == nil {
		passwords = openFile(fileName)
	}

	fmt.Println("Use an empty name to indicate that you are done.")
	for {
		name, err := readpass.DefaultPasswordPrompt("Name: ")
		if err != nil {
			errorf("%v", err)
			break
		} else if name == "" {
			break
		}

		rec, ok := passwords.Store[name]
		if ok && len(rec.Password) != 0 {
			if !overWrite {
				errorf("entry exists, not forcing overwrite")
				os.Exit(1)
			} else {
				errorf("*** warning: overwriting password")
			}
		} else if !ok {
			rec = &Record{
				Name: name,
			}
		}

		password, err := readpass.PasswordPromptBytes("Password: ")
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		} else if len(password) == 0 {
			errorf("no password entered")
			continue
		}
		rec.Password = password
		rec.Timestamp = time.Now().Unix()
		passwords.Store[name] = rec
	}
	saveFile(fileName, passwords)
}

// storeMeta adds metadata to the named record.
func storeMeta(fileName, name string) {
	passwords := openFile(fileName)
	defer passwords.Zero()
	rec, ok := passwords.Store[name]
	if !ok {
		rec = &Record{Name: name}
		password, err := readpass.PasswordPromptBytes("Password: ")
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		} else if len(password) == 0 {
			errorf("no password entered")
			os.Exit(1)
		}
		rec.Password = password
		defer zero(password)
	}

	if rec.Metadata == nil {
		rec.Metadata = map[string][]byte{}
	}

	fmt.Println("Enter metadata; use an empty line to indicate that you are done.")
	for {
		line, err := readpass.DefaultPasswordPrompt("key = value: ")
		if err != nil {
			errorf("%v", err)
			break
		} else if line == "" {
			break
		}

		meta := strings.SplitN(line, "=", 2)
		if len(meta) < 2 {
			errorf("Metadata should be in the form 'key=value'")
			continue
		}

		key := strings.TrimSpace(meta[0])
		val := strings.TrimSpace(meta[1])
		rec.Metadata[key] = []byte(val)
	}
	rec.Timestamp = time.Now().Unix()
	saveFile(fileName, passwords)
}

const pemLabel = "PASSWORD STORE"

// exportStore dumps the secured password store in PEM format. The
// store is never decrypted, and the same process could be
// accomplished fairly easily with Unix text processing tools. It is
// supplied as a convenience.
func exportDatabase(filename, outFile string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		errorf("%v", err)
		os.Exit(1)
	}

	p := &pem.Block{
		Type:  pemLabel,
		Bytes: data,
	}

	var out io.Writer
	if outFile == "-" {
		out = os.Stdout
	} else {
		out, err = os.Create(outFile)
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		}
	}
	fmt.Fprintf(out, "%s\n", string(pem.EncodeToMemory(p)))
}

// importStore takes a store exported as a PEM file and imports it by
// checking the PEM type, decoding the body from base64, and writing
// the resulting (still-encrypted) byte slice to disk.
func importStore(filename, inFile string) {
	var dataFile io.Reader
	var err error
	if inFile == "-" {
		dataFile = os.Stdin
	} else {
		dataFile, err = os.Open(inFile)
		if err != nil {
			errorf("%v", err)
			os.Exit(1)
		}
	}

	pemData, err := ioutil.ReadAll(dataFile)
	if err != nil {
		errorf("%v", err)
		os.Exit(1)
	}
	p, _ := pem.Decode(pemData)
	if p == nil {
		errorf("No PEM data found.")
		os.Exit(1)
	} else if p.Type != pemLabel {
		errorf("Invalid PEM type.")
		os.Exit(1)
	}

	err = ioutil.WriteFile(filename, p.Bytes, 0600)
	if err != nil {
		errorf("%v", err)
		os.Exit(1)
	}
}

// changePassword decrypts the password store, zeroises and nulls the
// password, and stores the blob to disk. Nulling the password causes
// encryptFile to prompt for a passphrase used to generate a new
// encryption key.
func changePassword(fileName string) {
	blob, err := decryptFile(fileName)
	if err != nil {
		errorf("%v", err)
		os.Exit(1)
	}
	defer zero(blob)
	zero(passphrase)
	passphrase = nil
	fmt.Println("Changing password...")
	err = encryptFile(fileName, blob)
	if err != nil {
		errorf("%v", err)
		os.Exit(1)
	}
}

func main() {
	defer zero(passphrase)

	baseFile := filepath.Join(os.Getenv("HOME"), ".passwords.db")
	fileName := flag.String("f", baseFile, "path to password store")
	chPass := flag.Bool("c", false, "change password")
	store := flag.Bool("s", false, "store a password")
	overWrite := flag.Bool("o", false, "overwrite existing password")
	remove := flag.Bool("r", false, "remove a password")
	list := flag.Bool("l", false, "list passwords")
	doExport := flag.Bool("export", false, "export password store in PEM format")
	doImport := flag.Bool("import", false, "import password store from PEM format")
	multi := flag.Bool("multi", false, "enter multiple passwords")
	meta := flag.Bool("m", false, "store metadata instead of passwords")
	clip := flag.Bool("x", false, "show password in a format suitable for exporting to clipboard")
	flag.Parse()

	if *doExport || *doImport {
		if flag.NArg() != 1 {
			errorf("need the PEM file specified as an argument.")
			os.Exit(1)
		}
		if *doExport {
			exportStore(*fileName, flag.Arg(0))
		} else {
			importStore(*fileName, flag.Arg(0))
		}
		return
	} else if *list {
		listRecords(*fileName)
		return
	} else if *chPass {
		changePassword(*fileName)
		return
	} else if *multi {
		storeMany(*fileName, *overWrite)
		return
	} else if flag.NArg() != 1 {
		errorf("please specify a single password to retrieve")
		os.Exit(1)
	}
	name := flag.Arg(0)

	if *store && !*meta {
		storeRecord(*fileName, name, *overWrite)
	} else if *store && *meta {
		storeMeta(*fileName, name)
	} else if *remove {
		if *meta {
			removeMeta(*fileName, name)
		} else {
			removeRecord(*fileName, name)
		}
	} else {
		retrieveRecord(*fileName, name, *meta, *clip)
	}
}
