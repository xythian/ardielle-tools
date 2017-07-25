package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/ardielle/ardielle-go/rdl"
	"go/format"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

func GenerateRpc(opts *generateOptions) error {
	banner := opts.banner
	schema := opts.schema
	outdir := opts.dirName
	ns := opts.ns
	librdl := opts.librdl
	name := strings.ToLower(string(schema.Name))
	if outdir == "" {
		outdir = "."
		name = name + "_rpc.go"
	} else if strings.HasSuffix(outdir, ".go") {
		name = filepath.Base(outdir)
		outdir = filepath.Dir(outdir)
	} else {
		name = name + "_rpc.go"
	}
	filepath := outdir + "/" + name
	out, file, _, err := outputWriter(filepath, "", ".go")
	if err != nil {
		return err
	}
	if file != nil {
		defer func() {
			file.Close()
			err := goFmt(filepath)
			if err != nil {
				fmt.Println("Warning: could not format go code:", err)
			}
		}()
	}
	gen := &reqRepGenerator{
		registry: rdl.NewTypeRegistry(schema),
		schema:   schema,
		name:     capitalize(string(schema.Name)),
		writer:   out,
		banner:   banner,
		ns:       ns,
		librdl:   librdl,
	}
	if err := gen.emitCode(true, true); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: generating rpc code: %v\n", err)
	}
	out.Flush()
	return gen.err
}

type reqRepGenerator struct {
	registry rdl.TypeRegistry
	schema   *rdl.Schema
	name     string
	writer   *bufio.Writer
	err      error
	banner   string
	ns       string
	librdl   string
}

const rrTemplate = `{{define "PREAMBLE"}}

{{header}}
package {{package}}

import (
	"bytes"
	"encoding/json"
	"fmt"
	rdl "{{rdlruntime}}"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"context"
{{if generateHandler}}
	"github.com/dimfeld/httptreemux"
	"log"
{{end}}
)

var _ = json.Marshal
var _ = fmt.Printf
var _ = rdl.BaseTypeAny
var _ = ioutil.NopCloser
{{end}}

{{define "HANDLER_BASE"}}

type {{handler}} interface {
{{range methods}}
   {{comment .Comment}}
   {{.Signature}}{{end}}
}

type {{handler}}Authorizor func(ctx context.Context, action string, resource string) (bool, error)
type {{handler}}Authenticator func(req *http.Request) (*http.Request, error)

type {{handler}}Options struct {
   BaseURL         string
   Authorizer      {{handler}}Authorizor
   Authenticator   {{handler}}Authenticator
}

type {{adaptor}} struct {
   opts *{{handler}}Options
   handler {{handler}}
}

func NewAdaptor(handler {{handler}}, opts *{{handler}}Options) http.Handler {
   baseURL := opts.BaseURL
	for strings.HasSuffix(baseURL, "/") {
		baseURL = baseURL[0 : len(baseURL)-1]
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		log.Fatal(err)
	}
	b := u.Path
	router := httptreemux.New()
	adaptor := &{{adaptor}}{opts : opts, handler : handler}
{{range methods}}
   	router.{{.Method}}(b+"{{.PathTemplate}}", adaptor.{{.AdaptorMethod}})
   {{- end}}
	router.NotFoundHandler = func(w http.ResponseWriter, r *http.Request) {
		rdl.JSONResponse(w, 404, rdl.ResourceError{Code: http.StatusNotFound, Message: "Not Found"})
	}
	log.Printf("Initialized Callbackd service at '%s'\n", baseURL)
	return router
}

func (adaptor *{{adaptor}}) sendErrorResponse(err error, w http.ResponseWriter) {
	switch e := err.(type) {
	case *rdl.ResourceError:
		rdl.JSONResponse(w, e.Code, err)
	default:
		rdl.JSONResponse(w, 500, &rdl.ResourceError{Code: 500, Message: e.Error()})
	}
}

{{end}}

{{define "CLIENT_BASE"}}

type {{client}} struct {
	URL         string
	Transport   http.RoundTripper
	CredsHeader *string
	CredsToken  *string
	Timeout     time.Duration
}

// NewClient creates and returns a new HTTP client object for the {{.Name}} service
func NewClient(url string, transport http.RoundTripper) {{client}} {
	return {{client}}{url, transport, nil, nil, 0}
}

// AddCredentials adds the credentials to the client for subsequent requests.
func (client *{{client}}) AddCredentials(header string, token string) {
	client.CredsHeader = &header
	client.CredsToken = &token
}

func (client {{client}}) getClient() *http.Client {
	var c *http.Client
	if client.Transport != nil {
		c = &http.Client{Transport: client.Transport}
	} else {
		c = &http.Client{}
	}
	if client.Timeout > 0 {
		c.Timeout = client.Timeout
	}
	return c
}

func (client {{client}}) addAuthHeader(req *http.Request) {
	if client.CredsHeader != nil && client.CredsToken != nil {
		if strings.HasPrefix(*client.CredsHeader, "Cookie.") {
			req.Header.Add("Cookie", (*client.CredsHeader)[7:]+"="+*client.CredsToken)
		} else {
			req.Header.Add(*client.CredsHeader, *client.CredsToken)
		}
	}
}

func (cl {{client}}) httpDo(ctx context.Context, req *http.Request) (*http.Response, error) {
   client := cl.getClient()
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
	   // get context error if there is one
		select {
		case <-ctx.Done():
			err = ctx.Err()
		default:
		}
	}
	return resp, err
}


func (client {{client}}) httpGet(ctx context.Context, url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	client.addAuthHeader(req)
    if headers != nil {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}
	return client.httpDo(ctx, req)
}

func (client {{client}}) httpDelete(ctx context.Context, url string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return nil, err
	}
	client.addAuthHeader(req)
    if headers != nil {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}
	return client.httpDo(ctx, req)
}

func (client {{client}}) httpPut(ctx context.Context, url string, headers map[string]string, body []byte) (*http.Response, error) {
	var contentReader io.Reader
	if body != nil {
		contentReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest("PUT", url, contentReader)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-type", "application/json")
	client.addAuthHeader(req)
    if headers != nil {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}
   return client.httpDo(ctx, req)
}

func (client {{client}}) httpPost(ctx context.Context, url string, headers map[string]string, body []byte) (*http.Response, error) {
	var contentReader io.Reader
	if body != nil {
		contentReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest("POST", url, contentReader)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-type", "application/json")
	client.addAuthHeader(req)
    if headers != nil {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}
   return client.httpDo(ctx, req)
}

func (client {{client}}) httpPatch(ctx context.Context, url string, headers map[string]string, body []byte) (*http.Response, error) {
	var contentReader io.Reader
	if body != nil {
		contentReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest("PATCH", url, contentReader)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-type", "application/json")
	client.addAuthHeader(req)
    if headers != nil {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}
   return client.httpDo(ctx, req)
}

func (client {{client}}) httpOptions(ctx context.Context, url string, headers map[string]string, body []byte) (*http.Response, error) {
	var contentReader io.Reader = nil
	if body != nil {
		contentReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest("OPTIONS", url, contentReader)
	if err != nil {
		return nil, err
	}
	if contentReader != nil {
		req.Header.Add("Content-type", "application/json")
	}
	client.addAuthHeader(req)
    if headers != nil {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}
   return client.httpDo(ctx, req)
}

func appendHeader(headers map[string]string, name, val string) map[string]string {
   if val == "" {
      return headers
   }
   if headers == nil {
      headers = make(map[string]string)
   }
   headers[name] = val
   return headers
}

func encodeStringParam(name string, val string, def string) string {
	if val == def {
		return ""
	}
	return "&" + name + "=" + url.QueryEscape(val)
}
func encodeBoolParam(name string, b bool, def bool) string {
	if b == def {
		return ""
	}
	return fmt.Sprintf("&%s=%v", name, b)
}
func encodeInt8Param(name string, i int8, def int8) string {
	if i == def {
		return ""
	}
	return "&" + name + "=" + strconv.Itoa(int(i))
}
func encodeInt16Param(name string, i int16, def int16) string {
	if i == def {
		return ""
	}
	return "&" + name + "=" + strconv.Itoa(int(i))
}
func encodeInt32Param(name string, i int32, def int32) string {
	if i == def {
		return ""
	}
	return "&" + name + "=" + strconv.Itoa(int(i))
}
func encodeInt64Param(name string, i int64, def int64) string {
	if i == def {
		return ""
	}
	return "&" + name + "=" + strconv.FormatInt(i, 10)
}
func encodeFloat32Param(name string, i float32, def float32) string {
	if i == def {
		return ""
	}
	return "&" + name + "=" + strconv.FormatFloat(float64(i), 'g', -1, 32)
}
func encodeFloat64Param(name string, i float64, def float64) string {
	if i == def {
		return ""
	}
	return "&" + name + "=" + strconv.FormatFloat(i, 'g', -1, 64)
}
func encodeOptionalEnumParam(name string, e interface{}) string {
	if e == nil {
		return "\"\""
	}
	return fmt.Sprintf("&%s=%v", name, e)
}
func encodeOptionalBoolParam(name string, b *bool) string {
	if b == nil {
		return ""
	}
	return fmt.Sprintf("&%s=%v", name, *b)
}
func encodeOptionalInt32Param(name string, i *int32) string {
	if i == nil {
		return ""
	}
	return "&" + name + "=" + strconv.Itoa(int(*i))
}
func encodeOptionalInt64Param(name string, i *int64) string {
	if i == nil {
		return ""
	}
	return "&" + name + "=" + strconv.Itoa(int(*i))
}
func encodeParams(objs ...string) string {
	s := strings.Join(objs, "&")
	if s == "" {
		return s
	}
	return "?" + s[1:]
}
{{end}}
{{define "FILE"}}
{{template "PREAMBLE"}}
{{if generateHandler}}
{{template "HANDLER_BASE"}}{{end}}
{{if generateClient}}
{{template "CLIENT_BASE"}}{{end}}

{{range methods}}
type {{.RequestName}} struct {
{{range .Inputs}}   {{.Name}} {{.TypeName}}
{{end}}
}

func Parse{{.RequestName}}(req *http.Request) (*{{.RequestName}}, error) {
    var req {{.RequestName}}
    var err error
{{range .Inputs }}
    {{.DecodeInputBlock}}
{{- end}}
    return &req, nil
}

type {{.ResponseName}} struct {
{{range .Outputs}}   {{.Name}} {{.TypeName}}
{{end}}
}

func (resp *{{.ResponseName}}) WriteResponse(w http.ResponseWriter, req *http.Request) {

}

{{if generateHandler}}

func (adaptor *{{adaptor}}) {{.AdaptorMethod}}(w http.ResponseWriter, req *http.Request, ps map[string]string) {
    // handle authentication
    if authReq, err := adaptor.opts.Authenticator(req); err != nil {
       adaptor.sendErrorResponse(err, w)
    } else if parsedRequest, err := Parse{{.RequestName}}(authReq); err != nil {
       adaptor.sendErrorResponse(err, w)
    } else {
        // handle authorization
        resp, err := adaptor.handler.{{.Name}}(authReq.Context(), parsedRequest)
        if err != nil {
           adaptor.sendErrorResponse(err, w)
        } else {
           // send response object as HTTP
			  resp.WriteResponse(w, req)
        }
    }
}
{{end}}
{{if generateClient}}
func (client {{client}}) {{.Signature}} {
	var response {{.ResponseName}}
	var headers map[string]string
	{{range .Inputs}}{{if (ne .Header  "")}}
	    headers = appendHeader(headers, "{{.Header}}", req.{{.Name}})
   {{end}}{{end}}
   url := client.URL + {{.URLExpression}}
   {{.Invocation}}
   if err != nil {
       return nil, err
   }
   outputBytes, err := ioutil.ReadAll(resp.Body)
   resp.Body.Close()
   if err != nil {
      return nil, err
   }
   switch resp.StatusCode {
   {{.ResponseCases}}
   default:
      var errobj rdl.ResourceError
      json.Unmarshal(outputBytes, &errobj)
	   if errobj.Code == 0 {
	      errobj.Code = resp.StatusCode
	   }
	   if errobj.Message == "" {
	      errobj.Message = string(outputBytes)
	   }
	   return nil, errobj
   }
   {{.ParseOutputHeaders}}
   return &response, nil
}
{{end}}

{{end}}
{{end}}`

func (gen *reqRepGenerator) emitCode(client, handler bool) error {
	commentFun := func(s string) string {
		return formatComment(s, 0, 80)
	}
	basenameFunc := func(s string) string {
		i := strings.LastIndex(s, ".")
		if i >= 0 {
			s = s[i+1:]
		}
		return s
	}

	methodFunc := func() []*reqRepMethod {
		output := make([]*reqRepMethod, 0, len(gen.schema.Resources))
		for _, r := range gen.schema.Resources {
			output = append(output, gen.convertResource(gen.registry, r))
		}
		return output
	}

	funcMap := template.FuncMap{
		"rdlruntime":      func() string { return gen.librdl },
		"header":          func() string { return generationHeader(gen.banner) },
		"package":         func() string { return generationPackage(gen.schema, gen.ns) },
		"basename":        basenameFunc,
		"comment":         commentFun,
		"methods":         methodFunc,
		"generateClient":  func() bool { return client },
		"generateHandler": func() bool { return handler },
		"client":          func() string { return gen.name + "Client" },
		"handler":         func() string { return gen.name + "Handler" },
		"adaptor":         func() string { return gen.name + "Adaptor" },
	}
	t := template.Must(template.New("REQREP_RPC_TEMPLATE").Funcs(funcMap).Parse(rrTemplate))
	var output bytes.Buffer
	if err := t.ExecuteTemplate(gen.writer, "FILE", gen.schema); err != nil {
		return err
	} else if data, err := format.Source(output.Bytes()); err != nil {
		return err
	} else if _, err := gen.writer.Write(data); err != nil {
		return err
	}
	gen.writer.Flush()
	return nil
}

type reqRepVar struct {
	Name                      string
	TypeName                  string
	ArrayType                 bool
	EncodeParameterExpression string
	DecodeInputBlock          string
	QueryParameter            string
	PathParameter             bool
	Header                    string
	Comment                   string
}

func (r *reqRepVar) IsBody() bool {
	return r.QueryParameter == "" && !r.PathParameter && r.Header == ""
}

type reqRepMethod struct {
	Resource        *rdl.Resource
	Name            string
	Method          string
	AdaptorMethod   string
	PathTemplate    string
	PathExpression  []string
	QueryExpression []string
	Comment         string
	RequestName     string
	ResponseName    string
	Inputs          []*reqRepVar
	Outputs         []*reqRepVar
}

func (m *reqRepMethod) Signature() string {
	return fmt.Sprintf("%s(ctx context.Context, req *%s) (*%s, error)", m.Name, m.RequestName, m.ResponseName)
}

func (m *reqRepMethod) URLExpression() string {
	// TODO: include Query Parameters
	exprs := m.PathExpression[:]
	if len(m.QueryExpression) > 0 {
		exprs = append(exprs, "encodeParams("+strings.Join(m.QueryExpression, ",")+")")
	}
	return fmt.Sprintf("fmt.Sprint(%s)", strings.Join(exprs, ","))
}

func (m *reqRepMethod) Invocation() string {
	method := capitalize(strings.ToLower(m.Method))
	findBodyParam := func() string {
		bodyParam := ""
		for _, in := range m.Inputs {
			if in.IsBody() {
				bodyParam = "req." + in.Name
				break
			}
		}
		return bodyParam
	}
	var s string
	switch method {
	case "Get", "Delete":
		s = "\tresp, err := client.http" + method + "(ctx, url, headers)\n"
	case "Put", "Post", "Patch":
		bodyParam := findBodyParam()
		if bodyParam == "" {
			s = "\tvar contentBytes []byte\n"
		} else {
			s = "\tcontentBytes, err := json.Marshal(" + bodyParam + ")\n"
			s += "\tif err != nil {\n\t\treturn nil, err\n\t}\n"
		}
		s += "\tresp, err := client.http" + method + "(ctx, url, headers, contentBytes)\n"
	case "Options":
		bodyParam := findBodyParam()
		if bodyParam != "" {
			s = "\tcontentBytes, err := json.Marshal(" + bodyParam + ")\n"
			s += "\tif err != nil {\n\t\treturn nil, err\n\t}\n"
			s += "\tresp, err := client.http" + method + "(ctx, url, headers, contentBytes)\n"
		} else {
			s = "\tresp, err := client.http" + method + "(ctx, url, headers, nil)\n"
		}
	}
	return s
}

type codeGen struct {
	buf bytes.Buffer
}

func (c *codeGen) Code() ([]byte, error) {
	return c.buf.Bytes(), nil
}

func (c *codeGen) CodeString() (string, error) {
	if b, err := c.Code(); err != nil {
		return "", err
	} else {
		return string(b), nil
	}

}

func (c *codeGen) Block(lines string) {
	c.Println(lines)
}

func (c *codeGen) Println(line string) {
	c.buf.WriteString(line + "\n")
}

func (c *codeGen) Printf(format string, args ...interface{}) {
	c.Println(fmt.Sprintf(format, args...))
}

func (m *reqRepMethod) ResponseCases() (string, error) {
	var s codeGen
	r := m.Resource
	expected := make(map[string]bool)
	expected[r.Expected] = true
	for _, e := range r.Alternatives {
		expected[e] = true
	}
	for expect, _ := range expected {
		code := rdl.StatusCode(expect)
		s.Printf("case %s:", code)
		switch expect {
		case "NO_CONTENT":
			fallthrough
		case "NOT_MODIFIED":
			// no body
		default:
			// decode body
			s.Println("if err := json.Unmarshal(outputBytes, &response.Body); err != nil {")
			s.Println("   return nil, err")
			s.Println("}")
		}
	}
	return s.CodeString()
}

func (m *reqRepMethod) ParseOutputHeaders() (string, error) {
	//here, define the output headers
	var code codeGen
	for _, out := range m.Outputs {
		if out.Header != "" {
			if out.TypeName != "string" {
				code.Printf("response.%s = %s(resp.Header.Get(rdl.FoldHttpHeaderName(%q))", out.Name, out.TypeName, out.Header)
			} else {
				code.Printf("response.%s = resp.Header.Get(rdl.FoldHttpHeaderName(%q)", out.Name, out.Header)
			}
		}
	}
	return code.CodeString()
}

func (m *reqRepMethod) goParamInitBlock(reg rdl.TypeRegistry, qname string, pname string, ptype rdl.TypeRef, pdefault interface{}, poptional bool, precise bool, prefixEnums bool) string {
	s := ""
	switch gtype {
	default:
		t := reg.FindType(ptype)
		bt := reg.BaseType(t)
		switch bt {
		case rdl.BaseTypeString:
			if pdefault == nil {
				if precise && gtype != "string" {
					s += "\t" + pname + " := " + gtype + "(rdl.OptionalStringParam(request, \"" + qname + "\"))\n"
				} else {
					s += "\t" + pname + " := rdl.OptionalStringParam(request, \"" + qname + "\")\n"
				}
			} else {
				def := fmt.Sprintf("%q", pdefault)
				if precise && gtype != "string" {
					s += "\t" + pname + "Val, _ := rdl.StringParam(request, \"" + qname + "\", " + def + ")\n"
					s += "\t" + pname + " := " + gtype + "(" + pname + "Val)\n"
				} else {
					s += "\t" + pname + ", _ := rdl.StringParam(request, \"" + qname + "\", " + def + ")\n"
				}
			}
		case rdl.BaseTypeInt32, rdl.BaseTypeInt16, rdl.BaseTypeInt8, rdl.BaseTypeInt64, rdl.BaseTypeFloat32, rdl.BaseTypeFloat64:
			stype := fmt.Sprint(bt)
			if pdefault == nil {
				s += "\t" + pname + ", err := rdl.Optional" + stype + "Param(request, \"" + qname + "\")\n" //!
				s += "\tif err != nil {\n\t\trdl.JSONResponse(writer, 400, err)\n\t\treturn\n\t}\n"
			} else {
				def := "0"
				switch v := pdefault.(type) {
				case float64:
					def = fmt.Sprintf("%v", v)
				default:
					fmt.Println("fix me:", pdefault)
					panic("fix me")
				}
				if precise {
					s += "\t" + pname + "_, err := rdl." + stype + "Param(request, \"" + qname + "\", " + def + ")\n"
				} else {
					s += "\t" + pname + ", err := rdl." + stype + "Param(request, \"" + qname + "\", " + def + ")\n"
				}
				s += "\tif err != nil {\n\t\trdl.JSONResponse(writer, 400, err)\n\t\treturn\n\t}\n"
				if precise {
					s += "\t" + pname + " := " + gtype + "(" + pname + "_)\n"
				}
			}
		case rdl.BaseTypeBool:
			if pdefault == nil {
				s += "\t" + pname + ", err := rdl.OptionalBoolParam(request, \"" + qname + "\")\n"
				s += "\tif err != nil {\n"
				s += "\t\trdl.JSONResponse(writer, 400, err)\n"
				s += "\t\treturn\n"
				s += "\t}\n"
			} else {
				def := fmt.Sprintf("%v", pdefault)
				s += "\tvar " + pname + "Optional " + gtype + " = " + def + "\n"
				s += "\t" + pname + ", err := rdl.BoolParam(request, \"" + qname + "\", " + pname + "Optional)\n"
				s += "\tif err != nil {\n"
				s += "\t\trdl.JSONResponse(writer, 400, err)\n"
				s += "\t\treturn\n"
				s += "\t}\n"
			}
		case rdl.BaseTypeEnum:
			if pdefault == nil {
				s += fmt.Sprintf("\tvar %s *%s\n", pname, gtype)
				s += fmt.Sprintf("\t%sOptional := rdl.OptionalStringParam(request, %q)\n", pname, qname)
				s += fmt.Sprintf("\tif %sOptional != \"\" {\n", pname)
				s += "\t\tp" + pname + " := New" + gtype + "(" + pname + "Optional)\n"
				s += "\t\t" + pname + " = &p" + pname + "\n"
				s += "\t}\n"
			} else {
				if prefixEnums {
					pdefault = gtype + SnakeToCamel(fmt.Sprint(pdefault))
				}
				s += fmt.Sprintf("\t%sOptional, _ := rdl.StringParam(request, %q, %v.String())\n", pname, qname, pdefault)
				if poptional {
					s += "\tp" + pname + " := New" + gtype + "(" + pname + "Optional)\n"
					s += "\t" + pname + " := &p" + pname + "\n"
				} else {
					s += "\t" + pname + " := New" + gtype + "(" + pname + "Optional)\n"
				}
			}
		default:
			fmt.Println("fix me:", pname, "of type", gtype, "with base type", bt)
			panic("fix me")
		}
	}
	return s
}

func (rr *reqRepGenerator) convertInput(reg rdl.TypeRegistry, v *rdl.ResourceInput) *reqRepVar {
	if v.Context != "" { //legacy field, to be removed
		return nil
	}
	res := &reqRepVar{
		Name:           capitalize(goName(string(v.Name))),
		Comment:        v.Comment,
		QueryParameter: v.QueryParam,
		PathParameter:  v.PathParam,
		Header:         v.Header,
		TypeName:       goType2(reg, v.Type, v.Optional, "", "", true, true, ""),
	}
	var decoder codeGen
	valueExpr := fmt.Sprintf("req.%s", res.Name)
	baseType := reg.BaseTypeName(v.Type)
	if v.Optional {
		if v.Default != nil {
			decoder.Println("%s = %s", valueExpr, goLiteral(v.Default, baseType))
		}
	}
	if reg.IsArrayTypeName(v.Type) && res.QueryParameter != "" {
		res.EncodeParameterExpression = fmt.Sprintf("encodeListParam(\"%s\", %s)", res.QueryParameter, valueExpr)
		decoder.Printf("if %s, err = decodeListParam(\"%s\") {", valueExpr, res.QueryParameter)
		decoder.Println("   return nil, err")
		decoder.Println("}")
	} else if res.QueryParameter != "" {
		baseType := reg.BaseTypeName(v.Type)
		if v.Optional && baseType != "String" {
			res.EncodeParameterExpression = "encodeOptional" + string(baseType) + "Param(\"" + res.QueryParameter + "\", " + valueExpr + ")"
		} else {
			def := goLiteral(v.Default, string(baseType))
			if baseType == "Enum" {
				def = "\"" + def + "\""
				res.EncodeParameterExpression = "encodeStringParam(\"" + res.QueryParameter + "\", " + valueExpr + ".String(), " + def + ")"
			} else {
				res.EncodeParameterExpression = "encode" + string(baseType) + "Param(\"" + res.QueryParameter + "\", " + strings.ToLower(string(baseType)) + "(" + valueExpr + "), " + def + ")"
			}
		}
	}
	res.DecodeInputBlock, _ = decoder.CodeString()
	return res
}

func (rr *reqRepGenerator) convertOutput(reg rdl.TypeRegistry, v *rdl.ResourceOutput) *reqRepVar {
	return &reqRepVar{
		Name:      capitalize(goName(string(v.Name))),
		Header:    v.Header,
		Comment:   v.Comment,
		ArrayType: reg.IsArrayTypeName(v.Type),
		TypeName:  goType2(reg, v.Type, v.Optional, "", "", true, true, ""),
	}
}

func (rr *reqRepGenerator) convertResource(reg rdl.TypeRegistry, r *rdl.Resource) *reqRepMethod {
	var method reqRepMethod
	bodyType := string(safeTypeVarName(r.Type))
	for _, v := range r.Inputs {
		if input := rr.convertInput(reg, v); input != nil {
			method.Inputs = append(method.Inputs, input)
			if input.IsBody() {
				bodyType = input.TypeName
			}
		}
	}
	noContent := r.Expected == "NO_CONTENT" && r.Alternatives == nil
	if !noContent {
		method.Outputs = append(method.Outputs, &reqRepVar{
			Name:     "Body",
			TypeName: goType(reg, r.Type, false, "", "", true, true),
		})
	}
	for _, v := range r.Outputs {
		if input := rr.convertOutput(reg, v); input != nil {
			method.Inputs = append(method.Inputs, input)
		}
	}
	method.Resource = r
	method.Name = string(r.Name)
	method.Method = r.Method
	method.Comment = r.Comment
	if method.Name == "" {
		methodTypeName := bodyType
		if strings.HasPrefix(methodTypeName, "*") {
			methodTypeName = methodTypeName[1:]
		}
		method.Name = capitalize(strings.ToLower(string(r.Method)) + methodTypeName)
	} else {
		method.Name = capitalize(method.Name)
	}
	method.AdaptorMethod = strings.ToLower(method.Name[:1]) + method.Name[1:]
	method.RequestName = method.Name + "Request"
	method.ResponseName = method.Name + "Response"
	findPathVariable := func(name string) *reqRepVar {
		for _, input := range method.Inputs {
			if input.PathParameter && strings.EqualFold(input.Name, name) {
				return input
			}
		}
		return nil
	}
	addPathLiteral := func(s string) {
		if s == "" {
			return
		}
		method.PathExpression = append(method.PathExpression, fmt.Sprintf("%#v", s))
		method.PathTemplate += s
	}
	addPathVariable := func(name string) {
		v := findPathVariable(name)
		if v == nil {
			// what to do? drop for now.
			return
		}
		method.PathExpression = append(method.PathExpression, fmt.Sprintf("req.%s", v.Name))
		method.PathTemplate += ":" + strings.ToLower(v.Name)
	}
	addQueryParameter := func(v *reqRepVar) {
		method.QueryExpression = append(method.QueryExpression, v.EncodeParameterExpression)
	}
	chunks := strings.Split(r.Path, "{")
	for _, chunk := range chunks {
		closeBrace := strings.Index(chunk, "}")
		rest := chunk
		if closeBrace >= 0 {
			varName := chunk[:closeBrace]
			rest = chunk[closeBrace+1:]
			addPathVariable(varName)
		}
		addPathLiteral(rest)
	}
	for _, v := range method.Inputs {
		if v.QueryParameter != "" {
			addQueryParameter(v)
		}
	}

	return &method
}
