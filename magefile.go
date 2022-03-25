// Copyright 2021 aletheia7. All rights reserved. Use of this source code is
// governed by a BSD-2-Clause license that can be found in the LICENSE file.
//go:build mage
// +build mage

package main

import (
	"erik.broadlux.com/gitmage"
	"github.com/magefile/mage/mg" // mg contains helpful utility functions, like Deps
	"github.com/magefile/mage/sh"
	"log"
)

var Default = All

// all
func All() {
	mg.Deps(Install)
}

// go clean
func Clean() error {
	log.Println("cleaning ...")
	return sh.RunV("go", "clean", "-cache")
}

// go install
func Install() error {
	return sh.RunV("go", "install", "-v", "-trimpath", `-ldflags`, "-s -w "+gitmage.Git())
}
