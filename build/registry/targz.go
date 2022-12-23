/*
Copyright (C) 2023 The Falco Authors.

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

package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path"
)

func tarGzSingleFile(outputPath string, fileName string) error {
	var file *os.File
	var err error
	var writer *gzip.Writer

	if file, err = os.OpenFile(outputPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644); err != nil {
		return err
	}
	defer file.Close()

	if writer, err = gzip.NewWriterLevel(file, gzip.DefaultCompression); err != nil {
		return err
	}
	defer writer.Close()

	tw := tar.NewWriter(writer)
	defer tw.Close()

	body, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}

	hdr := &tar.Header{
		Name: path.Base(fileName),
		Mode: int64(0644),
		Size: int64(len(body)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(body); err != nil {
		return err
	}

	return nil
}
