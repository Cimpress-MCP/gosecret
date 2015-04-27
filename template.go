package main

import (
  "bytes"
  "fmt"
  "io/ioutil"
  "path/filepath"
  "text/template"
)

type Template struct {
  // Path and key file name
  Path string

  contents string
}

// NewTemplate creates and parses a new Consul Template template at the given
// path. If the template does not exist, an error is returned. During
// initialization, the template is read and is parsed for dependencies. Any
// errors that occur are returned.
func NewTemplate(path string) (*Template, error) {
  template := &Template{Path: path}
  if err := template.init(); err != nil {
    return nil, err
  }

  return template, nil
}

//Execute missing
func (t *Template) Execute() ([]byte, error) {
  name := filepath.Base(t.Path)
  funcs := template.FuncMap{
    // Template functions
    "goEncrypt": goEncryptFunc,
    "goDecrypt": goDecryptFunc,
  }

  tmpl, err := template.New(name).Funcs(funcs).Parse(t.contents)
	if err != nil {
		return nil, fmt.Errorf("template: %s", err)
	}

  buff := new(bytes.Buffer)
	if err := tmpl.Execute(buff, nil); err != nil {
		return nil, fmt.Errorf("template: %s", err)
	}

  return buff.Bytes(), nil
}

// init reads the template file and initializes required variables.
func (t *Template) init() error {
	// Render the template
	contents, err := ioutil.ReadFile(t.Path)
	if err != nil {
		return err
	}
	t.contents = string(contents)

	return nil
}
