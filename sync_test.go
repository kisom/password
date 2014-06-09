package main

import (
	"bytes"
	"testing"
	"time"
)

var nowTime int64 = time.Now().Unix()

var testPasswords = &Passwords{
	Version:   version,
	Timestamp: time.Now().Unix(),
	Store: map[string]*Record{
		"example.net": {
			Name:      "example.net",
			Timestamp: nowTime,
			Password:  []byte("password-example.net"),
			Metadata: map[string][]byte{
				"account name": []byte("johnqpublic"),
			},
		},
		"example.org": {
			Name:      "example.org",
			Timestamp: nowTime - 5,
			Password:  []byte("password-example.org"),
		},
	},
}

var otherPasswords = &Passwords{
	Version:   version,
	Timestamp: time.Now().Unix(),
	Store: map[string]*Record{
		"example.com": {
			Name:      "example.com",
			Timestamp: nowTime,
			Password:  []byte("password-example.com"),
		},
		"example.net": {
			Name:      "example.net",
			Timestamp: nowTime - 120,
			Password:  []byte("wrong-password"),
		},
		"example.org": {
			Name:      "example.org",
			Timestamp: nowTime,
			Password:  []byte("changeme"),
			Metadata: map[string][]byte{
				"was changed?": []byte("very yes"),
			},
		},
	},
}

func testForAccount(m map[string]*Record, k string) bool {
	_, ok := m[k]
	return ok
}

func TestMergeSimple(t *testing.T) {
	testPasswords.Merge(otherPasswords)
	if len(testPasswords.Store) != 3 {
		t.Fatalf("Merge failed: expected 2 records, have %d",
			len(testPasswords.Store))
	}

	if !testForAccount(testPasswords.Store, "example.net") {
		t.Fatal("Missing example.net record.")
	}
	if !testForAccount(testPasswords.Store, "example.org") {
		t.Fatal("Missing example.org record.")
	}
	if !testForAccount(testPasswords.Store, "example.com") {
		t.Fatal("Missing example.com record.")
	}
}

func TestMergedExampleNet(t *testing.T) {
	password := testPasswords.Store["example.net"].Password
	if !bytes.Equal(password, []byte("password-example.net")) {
		t.Fatalf("Expected password 'password-example.net', have '%s'", password)
	}

	if len(testPasswords.Store["example.net"].Metadata) == 0 {
		t.Fatal("Metadata wasn't preserved during example.net merge.")
	}

	accountName := testPasswords.Store["example.net"].Metadata["account name"]
	if !bytes.Equal(accountName, []byte("johnqpublic")) {
		t.Fatalf("Expected metadata entry for 'account name' to be 'johnqpublic', have '%s'", accountName)
	}
}

func TestMergedExampleOrg(t *testing.T) {
	password := testPasswords.Store["example.org"].Password
	if !bytes.Equal(password, []byte("changeme")) {
		t.Fatalf("Expected password 'changeme', have '%s'", password)
	}

	if len(testPasswords.Store["example.org"].Metadata) == 0 {
		t.Fatal("Metadata wasn't preserved during example.net merge.")
	}

	wasChanged := testPasswords.Store["example.org"].Metadata["was changed?"]
	if !bytes.Equal(wasChanged, []byte("very yes")) {
		t.Fatalf("Expected metadata entry for 'was changed?' to be 'very yes', have '%s'", wasChanged)
	}

}
