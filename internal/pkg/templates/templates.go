package templates

import (
	"embed"
	"io"
	"text/template"
)

//go:embed *.tmpl
var tfs embed.FS

func ExecuteTemplate(w io.Writer, name string, data any) error {
	t, err := template.New("").ParseFS(tfs, "templates/page.tmpl", "templates/"+name+".tmpl")
	if err != nil {
		return err
	}

	return t.ExecuteTemplate(w, "page", data)
}
