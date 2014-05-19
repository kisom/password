// Command line password manager.
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

	"github.com/gokyle/readpass"
)

var passphrase []byte

type Record struct {
	Name     string
	Password []byte
	Metadata map[string][]byte
}

func (r *Record) Zero() {
	if r == nil {
		return
	}

	zero(r.Password)
	for k := range r.Metadata {
		zero(r.Metadata[k])
	}
}

func (r *Record) Display(showMetadata, clipExport bool) {
	if !clipExport {
		fmt.Printf("Password: %q\n", r.Password)
	} else {
		fmt.Printf("%s", r.Password)
		return
	}
	if showMetadata {
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

type Passwords map[string]*Record

func (p Passwords) Zero() {
	for k := range p {
		p[k].Zero()
	}
}

var passwords Passwords

func openFile(fileName string) Passwords {
	fileData, err := decryptFile(fileName)
	if err != nil {
		errorf("Failed to open password file: %v", err)
		os.Exit(1)
	}

	var passwords Passwords
	err = json.Unmarshal(fileData, &passwords)
	if err != nil {
		errorf("Failed to open password file: %v", err)
		os.Exit(1)
	}
	return passwords
}

func saveFile(fileName string, passwords Passwords) {
	encoded, err := json.Marshal(passwords)
	if err != nil {
		errorf("Failed to serialise password store: %v", err)
		os.Exit(1)
	}
	defer zero(encoded)

	err = encryptFile(fileName, encoded)
	if err != nil {
		errorf("%v", err)
		os.Exit(1)
	}
}

func retrieveRecord(fileName, name string, showMetadata, clipExport bool) {
	passwords := openFile(fileName)
	defer passwords.Zero()
	rec, ok := passwords[name]
	if !ok {
		errorf("entry not found")
		os.Exit(1)
	}
	rec.Display(showMetadata, clipExport)
}

func listRecords(fileName string) {
	passwords := openFile(fileName)
	defer passwords.Zero()

	if len(passwords) == 0 {
		fmt.Printf("no passwords")
		return
	}

	var names = make([]string, 0, len(passwords))
	fmt.Println("Names:")
	for k, _ := range passwords {
		names = append(names, k)
	}
	sort.Strings(names)

	for _, name := range names {
		fmt.Printf("\t%s\n", name)
	}
}

func removeRecord(fileName, name string) {
	passwords := openFile(fileName)
	defer passwords.Zero()

	delete(passwords, name)
	saveFile(fileName, passwords)
	fmt.Println("Done.")
}

func storeRecord(fileName, name string, overWrite bool) {
	var passwords = Passwords{}
	defer passwords.Zero()

	if _, err := os.Stat(fileName); err != nil && !os.IsNotExist(err) {
		errorf("Failed to open password store: %v", err)
		os.Exit(1)
	} else if err == nil {
		passwords = openFile(fileName)
	}

	_, ok := passwords[name]
	if ok {
		if !overWrite {
			errorf("entry exists, not forcing overwrite")
			os.Exit(1)
		} else {
			errorf("*** warning: overwriting password")
		}
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
	passwords[name] = &Record{
		Name:     name,
		Password: password,
	}
	saveFile(fileName, passwords)
}

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

		rec, ok := passwords[name]
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
		passwords[name] = rec
	}
	saveFile(fileName, passwords)
}

func storeMeta(fileName, name string) {
	passwords := openFile(fileName)
	defer passwords.Zero()
	rec, ok := passwords[name]
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
	passwords[name] = rec
	saveFile(fileName, passwords)
}

const pemLabel = "PASSWORD STORE"

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

func importDatabase(filename, inFile string) {
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
			exportDatabase(*fileName, flag.Arg(0))
		} else {
			importDatabase(*fileName, flag.Arg(0))
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
		removeRecord(*fileName, name)
	} else {
		retrieveRecord(*fileName, name, *meta, *clip)
	}
}
