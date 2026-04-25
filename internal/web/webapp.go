package web

import "github.com/gin-gonic/gin"

// TemplateFile is the conventional template file name shared by plugin web UIs.
const TemplateFile = "web.tmpl"

// WebApp is a thin wrapper around a gin.Engine providing the conventions
// shared by plugin web frontends (a default engine, optional template file).
// Plugins register their routes directly on the embedded *gin.Engine and use
// Run(addr) (provided by gin.Engine) to start the server.
type WebApp struct {
	*gin.Engine
}

// NewWebApp returns a WebApp with a default gin.Engine. Templates are not
// loaded; call LoadTemplate to load the conventional TemplateFile.
func NewWebApp() *WebApp {
	return &WebApp{Engine: gin.Default()}
}

// LoadTemplate loads the conventional TemplateFile into the underlying engine.
func (w *WebApp) LoadTemplate() {
	w.LoadHTMLFiles(TemplateFile)
}

// Run starts the underlying gin engine listening on addr, satisfying WebRunner.
func (w *WebApp) Run(addr string) error {
	return w.Engine.Run(addr)
}
