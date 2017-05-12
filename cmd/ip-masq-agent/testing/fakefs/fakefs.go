/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fakefs

import (
	"errors"
	"io/ioutil"
	"os"
	"time"
)

type FileSystem interface {
	Stat(name string) (os.FileInfo, error)
	ReadFile(name string) ([]byte, error)
}

// DefaultFS implements FileSystem using the local disk
type DefaultFS struct{}

func (DefaultFS) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}
func (DefaultFS) ReadFile(name string) ([]byte, error) {
	return ioutil.ReadFile(name)
}

// StringFS returns the string as the contents of the file
type StringFS struct {
	File string
}

func (fs StringFS) Stat(name string) (os.FileInfo, error) {
	f := NewFileInfo()
	f.name = name
	f.size = int64(len([]byte(fs.File)))
	return f, nil
}
func (fs StringFS) ReadFile(name string) ([]byte, error) {
	return []byte(fs.File), nil
}

// NotExistFS will always return os.ErrNotExist type errors from calls to Stat
type NotExistFS struct{}

func (NotExistFS) Stat(name string) (os.FileInfo, error) {
	return nil, os.ErrNotExist
}
func (NotExistFS) ReadFile(name string) ([]byte, error) {
	return []byte{},
		&os.PathError{
			Op:   "open",
			Path: name,
			Err:  errors.New("errno 2"), // errno 2 is ENOENT, since the file shouldn't exist
		}
}

// FileInfo implements the os.FileInfo interface
type FileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
	isDir   bool
	sys     interface{}
}

func (f *FileInfo) Name() string       { return f.name }
func (f *FileInfo) Size() int64        { return f.size }
func (f *FileInfo) Mode() os.FileMode  { return f.mode }
func (f *FileInfo) ModTime() time.Time { return f.modTime }
func (f *FileInfo) IsDir() bool        { return f.isDir }
func (f *FileInfo) Sys() interface{}   { return f.sys }

func NewFileInfo() *FileInfo {
	return &FileInfo{
		name:    "",
		size:    0,
		mode:    os.FileMode(0777),
		modTime: time.Time{}, // just use zero time
		isDir:   false,
		sys:     nil,
	}
}
