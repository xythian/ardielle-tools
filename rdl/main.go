// Copyright 2015 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/ardielle/ardielle-go/rdl"
	"github.com/jawher/mow.cli"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// BuildDate is set when building to contain the build date
var BuildDate string

func usage() {
	msg := `
Usage: rdl [OPTIONS] COMMAND [arg...]

Parse and process an RDL file.

Options:
  -p           show errors and non-exported results in a prettier way (default is false)
  -w           suppress warnings (default is false)
  -s           parse in strict mode (default is false)

Commands:
  help
  version
  parse <schemafile.rdl>
  validate <datafile.json> <schemafile.rdl> [<typename>]
  generate [-elt] [-o <outfile>] <generator> <schema.rdl>
  import [-o <outfile>] external_type external_file

Generator Options:
  -o path         Use the directory or file as output for generation. Default is stdout.
  -b path         Specify the base path of the URL for server and client generators.
  -e              Generate Enum constants prefixed by the type name to avoid collisions (default is false)
  --ns namespace  Use the specified namespace for code generation. Default is to use the namespace in the schema.
  -t              Generate precise type models, i.e. model string and numeric subtypes in Go (default is false)
  -l package      Generate code that imports this package as 'rdl' for base type impl (instead of standard rdl library)
  -u type         Generate the specified union type to JSON serialize as an untagged union. Default is a tagged.
  -x key=value    Set options for external generator, e.g. -x e=true -xfoo=bar will send -e true --foo bar to external generator.

Generators (accepted arguments to the generate command):
  json               Generate the JSON representation of the schema
  markdown           Generate the markdown representation of the schema and its comments
  go-model           Generate the Go code for the types in the schema
  go-client          Generate the Go code for a client to the resources in the schema
  go-server          Generate the Go code for a server implementation  of the resources in the schema
  go-server-project  Generate the project directory containing Go code for server and model and a mock implementation
  java-model         Generate the Java code for the types in the schema
  java-client        Generate the Java code for a client to the resources in the schema
  java-server        Generate the Java code for a server implementation  of the resources in the schema
  swagger            Generate the swagger resource for the schema. If the outfile is an endpoint, serve it via HTTP.
  legacy             Generate the legacy (RDL v1) JSON representation of the schema

  <name>             Invoke an external generator named 'rdl-gen-<name>', searched for in your $PATH. The
                     generator is passed the -o flag if it was set, and the JSON representation of the schema
                     is written to its stdin.

`
	fmt.Fprintf(os.Stderr, msg)
	os.Exit(0)
}

func main() {
	banner := "rdl (development version)"
	if rdl.Version != "" {
		banner = fmt.Sprintf("rdl %s", rdl.Version)
	}

	if len(os.Args) == 1 {
		usage()
	}
	app := cli.App("rdl", "Parse and process an RDL file")
	//Q: how can I override  mow.cli's usage? It is not good.
	pretty := app.BoolOpt("p pretty", false, "show errors and non-exported results in a prettier way")
	warning := app.BoolOpt("w nowarn", false, "suppress warnings")
	strict := app.BoolOpt("s strict", false, "parse in strict mode")

	app.Command("help", "Print extended help information and exit", func(cmd *cli.Cmd) {
		usage()
	})

	app.Command("version", "Print the version of this command and exit", func(cmd *cli.Cmd) {
		fmt.Printf("%s %s\n", banner, BuildDate)
		os.Exit(0)
	})

	app.Command("import", "import the specified file and output the equivalent RDL file", func(cmd *cli.Cmd) {
		pExtType := cmd.StringArg("TYPE", "", "the type of external schema, i.e. 'swagger'")
		pExtFile := cmd.StringArg("FILE", "", "the external file to import, i.e. 'foo.json'")
		pOutput := cmd.StringOpt("o", ".", "Output directory for result. Default is current directory")
		cmd.Action = func() {
			importSchema(*pExtType, *pExtFile, *pOutput)
		}
	})

	app.Command("parse", "parse the specified rdl file, to check syntax", func(cmd *cli.Cmd) {
		schemaFile := cmd.StringArg("FILE", "", "the rdl file defining the schema")
		cmd.Spec = "FILE"
		cmd.Action = func() {
			parse(*schemaFile, *pretty, *warning, *strict)
		}
	})

	app.Command("unparse", "Regenerate RDL source for the schema JSON file", func(cmd *cli.Cmd) {
		schemaFile := cmd.StringArg("FILE", "", "the json defining the schema")
		pOutput := cmd.StringOpt("o", ".", "Output directory for result. Default is the current directory")
		cmd.Action = func() {
			unparse(*schemaFile, *pOutput)
		}
	})

	app.Command("validate", "validate the specified data file for adherence to the schema", func(cmd *cli.Cmd) {
		dataFile := cmd.StringArg("DATA", "", "a JSON file containing the data")
		schemaFile := cmd.StringArg("FILE", "", "the rdl file defining the schema")
		dataType := cmd.StringArg("TYPENAME", "", "the name of the type in the schema for the data. By default, it is guessed")
		cmd.Spec = "DATA FILE [TYPENAME]"
		cmd.Action = func() {
			schema, _ := parse(*schemaFile, *pretty, *warning, *strict)
			validate(schema, *dataFile, *dataType, *pretty)
		}
	})

	app.Command("generate", "generate output from the schema, using the specified generator", func(cmd *cli.Cmd) {
		outfile := cmd.StringOpt("o", "", "Output file or directory for generated file(s). Default is stdout")
		preciseTypes := cmd.BoolOpt("t", false, "preserve string and scalar subtypes, if the language supports it")
		librdl := cmd.StringOpt("l", RdlGoImport, "Depends on this 'rdl' package for base types (default is "+RdlGoImport+")")
		untaggedUnions := cmd.StringsOpt("u", []string{}, "make this union type JSON serialize as an untagged union")
		prefixEnums := cmd.BoolOpt("e", false, "Prefixes enum constant names with their typename (default = false)")
		ns := cmd.StringOpt("ns", "", "Namespace for the code generation (default = schema namespace)")
		basePath := cmd.StringOpt("b", "", "Specify the base path of the URL for java server and client generators (default = schema name, snake-cased)")
		externalOptions := cmd.StringsOpt("x", []string{}, "Set options for external generator, e.g. -x e=true -xfoo=bar will send -e true --foo bar to external generator")
		requestResponse := cmd.BoolOpt("with-request-response", false, "Enable request/response objects")
		generator := cmd.StringArg("GENERATOR", "", "the generator to use")
		schemaFile := cmd.StringArg("FILE", "", "the rdl file defining the schema")
		cmd.Action = func() {
			schema, name := parse(*schemaFile, *pretty, *warning, *strict)
			if schema.Name == "" {
				schema.Name = name
			}
			opts := &generateOptions{
				schema:          schema,
				banner:          banner,
				dirName:         *outfile,
				librdl:          *librdl,
				requestResponse: *requestResponse,
				prefixEnums:     *prefixEnums,
				preciseTypes:    *preciseTypes,
				ns:              *ns,
				untaggedUnions:  *untaggedUnions,
				base:            *basePath,
				externalOptions: *externalOptions,
			}
			generate(*generator, *schemaFile, opts)
		}
	})
	app.Run(os.Args)
	os.Exit(0)
}

func parse(schemaFile string, pretty bool, warning bool, strict bool) (*rdl.Schema, rdl.Identifier) {
	var err error
	var schema *rdl.Schema
	file := filepath.Base(schemaFile)
	ext := filepath.Ext(file)
	name := file[0 : len(file)-len(ext)]
	switch ext {
	case ".json":
		data, err := ioutil.ReadFile(schemaFile)
		exitOnError(err)
		err = json.Unmarshal(data, &schema)
		//to do: an option to validate this against schema.rdl. The Schema type is closed, but
		//go's json reader (to a struct) just ignores fields it can't use, so we dont' get an error.
		exitOnError(err)
	default:
		schema, err = rdl.ParseRDLFile(schemaFile, pretty, strict, warning)
		exitOnError(err)
	}
	return schema, rdl.Identifier(name)
}

func unparse(schemaFile string, outdir string) {
	var err error
	var schema *rdl.Schema
	file := filepath.Base(schemaFile)
	ext := filepath.Ext(file)
	switch ext {
	case ".rdl":
		schema, err = rdl.ParseRDLFile(schemaFile, true, true, false)
		exitOnError(err)
	case ".json":
		data, err := ioutil.ReadFile(schemaFile)
		exitOnError(err)
		err = json.Unmarshal(data, &schema)
		exitOnError(err)
	}
	err = os.MkdirAll(outdir, 0755)
	exitOnError(err)
	fname := file
	if schema.Name != "" {
		fname = string(schema.Name)
	}
	err = rdl.UnparseRDLFile(schema, outdir+"/"+fname+".rdl")
	exitOnError(err)
}

func validate(schema *rdl.Schema, filename string, typename string, pretty bool) {
	data, err := readData(schema, filename, typename)
	if err == nil {
		validation := rdl.Validate(schema, typename, data)
		if validation.Error != "" {
			err = fmt.Errorf("Validation error (%s): %s", validation.Context, validation.Error)
		} else {
			if pretty {
				j, err := json.MarshalIndent(validation, "", "    ")
				if err == nil {
					fmt.Println(string(j))
				}
			}
		}
	}
	exitOnError(err)
}

func readData(schema *rdl.Schema, filename string, typename string) (interface{}, error) {
	bytes, err := ioutil.ReadFile(filename)
	if err == nil {
		var data interface{}
		err = json.Unmarshal(bytes, &data)
		if err == nil {
			return data, nil
		}
	}
	return nil, err
}

func ensureExtension(name string, ext string) string {
	if name == "" {
		return name
	}
	if strings.HasSuffix(name, ext) {
		return name
	}
	return name + ext
}

type generateOptions struct {
	schemaFile      string
	banner          string
	requestResponse bool
	dirName         string
	librdl          string
	prefixEnums     bool
	preciseTypes    bool
	ns              string
	schema          *rdl.Schema
	untaggedUnions  []string
	base            string
	externalOptions []string
}

func generate(flavor string, srcFile string, opts *generateOptions) {
	var err error
	switch flavor {
	case "json":
		err = rdl.ExportToJSON(opts.schema, opts.dirName)
	case "go-model":
		err = GenerateGoModel(opts)
	case "go-server":
		err = GenerateGoServer(opts)
	case "go-client":
		err = GenerateGoClient(opts)
	case "go-rpc":
		// Generate client and server stubs using the reqrep model
		opts.requestResponse = true
		if err = GenerateGoModel(opts); err == nil {
			err = GenerateRpc(opts)
		}
	case "go-server-project":
		err = GenerateGoServerProject(opts)
	case "java-model":
		err = GenerateJavaModel(opts.banner, opts.schema, opts.dirName, opts.ns, opts.externalOptions)
	case "java-server":
		err = GenerateJavaServer(opts.banner, opts.schema, opts.dirName, opts.ns, opts.base, opts.externalOptions)
	case "java-client":
		err = GenerateJavaClient(opts.banner, opts.schema, opts.dirName, opts.ns, opts.base, opts.externalOptions)
	default:
		err = generateExternally(flavor, opts.dirName, opts.schema, srcFile, opts.base, opts.externalOptions)
	}
	exitOnError(err)
}

func exitOnError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "*** %v\n", err)
		os.Exit(1)
	}
}

func generateExternally(flavor string, dirName string, schema *rdl.Schema, srcFile string, base string, options []string) error {
	cmd := "rdl-gen-" + flavor
	var argv []string
	if dirName != "" {
		argv = append(argv, "-o")
		argv = append(argv, dirName)
	}
	argv = append(argv, "-s")
	argv = append(argv, srcFile)
	if base != "" {
		argv = append(argv, "-b")
		argv = append(argv, base)
	}
	for _, option := range options {
		substrings := strings.SplitN(option, "=", 2)
		if len(substrings[0]) > 1 {
			argv = append(argv, "--"+substrings[0])
		} else {
			argv = append(argv, "-"+substrings[0])
		}
		if len(substrings) > 1 {
			argv = append(argv, substrings[1])
		}
	}
	return callSubcommand(cmd, argv, schema)
}

func callSubcommand(command string, argv []string, schema *rdl.Schema) error {
	cmd := exec.Command(command, argv...)
	j, err := json.Marshal(schema)
	if err != nil {
		fmt.Fprintf(os.Stderr, "*** %v\n", err)
		return err
	}
	cmd.Stdin = strings.NewReader(string(j))
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err = cmd.Run()
	serr := stderr.String()
	sout := stdout.String()
	if len(sout) > 0 {
		fmt.Printf("%s", sout)
	}
	if len(serr) > 0 {
		fmt.Fprintf(os.Stderr, "%s", serr)
	}
	return err
}

func importSchema(extType, extFile, outdir string) {
	cmd := "rdl-import-" + extType
	argv := []string{extFile}
	c := exec.Command(cmd, argv...)
	var stdout bytes.Buffer
	c.Stdout = &stdout
	var stderr bytes.Buffer
	c.Stderr = &stderr
	err := c.Run()
	serr := stderr.String()
	sout := stdout.String()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", serr)
	} else {
		var schema *rdl.Schema
		err = json.Unmarshal([]byte(sout), &schema)
		if err != nil {
			fmt.Fprintf(os.Stderr, "*** Cannnot unmarshal importer result: %v\n", err)
		} else {
			decompile(schema, outdir)
		}
	}
}

func getString(obj map[string]interface{}, spath string) string {
	path := strings.Split(spath, ".")
	if len(path) > 1 {
		for _, key := range path[:len(path)-1] {
			if o, ok := obj[key]; ok {
				if v, ok := o.(map[string]interface{}); ok {
					obj = v
					continue
				}
			}
			return ""
		}
	}
	if o, ok := obj[path[len(path)-1]]; ok {
		if s, ok := o.(string); ok {
			return s
		}
	}
	return ""
}

func decompile(schema *rdl.Schema, outdir string) {
	var err error
	fname := string(schema.Name)
	err = rdl.UnparseRDLFile(schema, outdir+"/"+fname+".rdl")
	if err != nil {
		fmt.Fprintf(os.Stderr, "*** %v\n", err)
	}
}
