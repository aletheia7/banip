// Copyright 2021 aletheia7. All rights reserved. Use of this source code is
// governed by a BSD-2-Clause license that can be found in the LICENSE file.

// Package jep parses systemd journal export format readers
package jep

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
)

type Entry map[string]string

type option func(*scanner)

// Used with New. Example: jep.Buffer(100_000)
func Buffer(max int) option {
	return func(o *scanner) {
		o.buffer_size = max
	}
}

// New provides a channel of parsed journal rows. Each Entry is a map of one journal line.
// Each journal lines is composed of multiple fields.
//
// BUG(aletheia7): Journal fields can have duplicates. Entry is a map and will only provide
// the last duplicated journal field. Duplicate fields are very rare and I have not seen
// one. Entry is a map in order to support quick lookups.
func New(ctx context.Context, r io.Reader, opt ...option) (chan Entry, Error) {
	o := new_scanner()
	for _, op := range opt {
		op(o)
	}
	go func() {
		defer close(o.C)
		scanner := bufio.NewScanner(r)
		if 0 < o.buffer_size {
			scanner.Buffer(make([]byte, o.buffer_size), o.buffer_size)
		}
		scanner.Split(o.Split)
		for scanner.Scan() && ctx.Err() == nil {
		}
		o.err = scanner.Err()
	}()
	return o.C, o
}

type scanner struct {
	C           chan Entry
	entry       Entry
	err         error
	buffer_size int
}

type Error interface {
	Error() error
}

func new_scanner() *scanner {
	return &scanner{
		C:     make(chan Entry, 1000),
		entry: Entry{},
	}
}

func (o *scanner) Error() error {
	return o.err
}

func (o *scanner) Split(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) < 2 {
		return
	}
	switch {
	case data[0] == '\n' && data[1] == '\n':
		advance = 2
		token = data[0:0] // scanner bombs with nil token
		o.C <- o.entry
		o.entry = Entry{}
		return
	case data[0] == '\n':
		advance = 1
		token = data[0:1] // scanner bombs with nil token
		return
	}
	// rel: relative position
	rel_equal_nl_pos := bytes.IndexAny(data, "=\n")
	switch {
	case rel_equal_nl_pos == -1:
		return
	case data[rel_equal_nl_pos] == '=':
		// Text field/value
		rel_nl_pos := bytes.IndexByte(data[rel_equal_nl_pos:], '\n')
		if rel_nl_pos == -1 {
			return
		}
		// Have complete text value
		// $$$abc=deff\n
		// field_start_pos = 3
		// rel_equal_nl_pos = 3
		// rel_nl_pos = 4
		// data[3:3 + 3 + 4 + 1] = abc=deff
		advance = rel_equal_nl_pos + rel_nl_pos
		token = data[0:0] // scanner bombs with nil token
		o.entry[string(data[:rel_equal_nl_pos])] = string(data[rel_equal_nl_pos+1 : rel_equal_nl_pos+rel_nl_pos])
		return
	}
	// Binary field/value
	// abs: absolute position
	abs_bin_end_pos := rel_equal_nl_pos + 1 + 8
	if len(data) < abs_bin_end_pos {
		return
	}
	abs_nl_pos := abs_bin_end_pos + int(binary.LittleEndian.Uint64(data[rel_equal_nl_pos+1:abs_bin_end_pos]))
	if len(data) < abs_nl_pos+1 {
		return
	}
	if data[abs_nl_pos] == '\n' {
		advance = abs_nl_pos
		token = data[0:0]
		o.entry[string(data[:rel_equal_nl_pos+1])] = string(data[abs_bin_end_pos:abs_nl_pos])
		return
	}
	// Seek past garbage. Should never get here. Protocol is violated.
	advance = abs_nl_pos + 1
	return
}
