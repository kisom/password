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

func (r *Record) Display(showMetadata bool) {
	fmt.Printf("Password: %q\n", r.Password)
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
		errorf("Failed to serialise accounts: %v", err)
		os.Exit(1)
	}
	defer zero(encoded)

	err = encryptFile(fileName, encoded)
	if err != nil {
		errorf("%v", err)
		os.Exit(1)
	}
}

func retrieveRecord(fileName, name string, showMetadata bool) {
	passwords := openFile(fileName)
	defer passwords.Zero()
	rec, ok := passwords[name]
	if !ok {
		errorf("entry not found")
		os.Exit(1)
	}
	rec.Display(showMetadata)
}

func listRecords(fileName string) {
	passwords := openFile(fileName)
	defer passwords.Zero()

	if len(passwords) == 0 {
		fmt.Printf("no passwords")
		return
	}
	fmt.Printf("Names:")
	for k, _ := range passwords {
		fmt.Printf("\t%s\n", k)
	}
}

func removeRecord(fileName, name string) {
	passwords := openFile(fileName)
	defer passwords.Zero()

	delete(passwords, name)
	saveFile(fileName, passwords)
}

func storeRecord(fileName, name string, overWrite bool) {
	var passwords = Passwords{}
	defer passwords.Zero()

	if _, err := os.Stat(fileName); err != nil && !os.IsNotExist(err) {
		errorf("Failed to open account store: %v", err)
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

func main() {
	defer zero(passphrase)

	baseFile := filepath.Join(os.Getenv("HOME"), ".passwords.db")
	fileName := flag.String("f", baseFile, "path to account store")
	store := flag.Bool("s", false, "store a password")
	overwrite := flag.Bool("o", false, "overwrite existing password")
	remove := flag.Bool("r", false, "remove a password")
	list := flag.Bool("l", false, "list passwords")
	doExport := flag.Bool("export", false, "export database in PEM format to stdout")
	doImport := flag.Bool("import", false, "import database from PEM format")
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
	} else if flag.NArg() != 1 {
		errorf("please specify a single password to retrieve")
		os.Exit(1)
	}
	name := flag.Arg(0)

	if *store {
		storeRecord(*fileName, name, *overwrite)
	} else if *remove {
		removeRecord(*fileName, name)
	} else {
		// TODO(kyle): store metadata
		retrieveRecord(*fileName, name, false)
	}
}
