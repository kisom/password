package main

// This file contains code for merging records and synchronising password
// stores.

// Merge compares the timestamp of the record to the other record;
// the record that was modified most recently is selected.
func (r *Record) Merge(other *Record) *Record {
	if r.Timestamp >= other.Timestamp {
		return r
	}
	return other
}

// Merge handles the merging of two password stores. For each record
// in the other password store, if the entry doesn't exist in the password
// store it is added. If it does exist, the two records are merged.
func (p *Passwords) Merge(other *Passwords) {
	for k, v := range other.Store {
		if r, ok := p.Store[k]; !ok {
			p.Store[k] = v
		} else {
			p.Store[k] = r.Merge(v)
		}
	}
}
