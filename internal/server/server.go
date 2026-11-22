package server

import (
	"context"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/jsandas/tls-client-scanner/internal/analyzer"
	"github.com/jsandas/tls-client-scanner/internal/capture"
	"github.com/jsandas/tls-client-scanner/internal/report"
)

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 15 * time.Second
	idleTimeout       = 60 * time.Second
)

//go:embed templates/report.html
var templateFiles embed.FS

// Server hosts the HTTPS report application.
type Server struct {
	httpServer *http.Server
	listener   net.Listener
}

// New creates a listening HTTPS server.
func New(address string, tlsConfig *tls.Config) (*Server, error) {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", address, err)
	}

	templates, err := loadTemplates()
	if err != nil {
		_ = listener.Close()

		return nil, err
	}

	config := tlsConfig.Clone()
	previousCallback := config.GetConfigForClient
	config.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		capture.Observe(info)

		if previousCallback != nil {
			return previousCallback(info)
		}

		return nil, nil
	}

	applicationListener := capture.Listener{Listener: listener}
	tlsListener := tls.NewListener(applicationListener, config)
	handler := NewHandler(templates)
	httpServer := &http.Server{
		Handler:           handler,
		ConnContext:       capture.ConnContext,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	return &Server{
		httpServer: httpServer,
		listener:   tlsListener,
	}, nil
}

// Serve serves requests until the server stops or the context expires.
func (s *Server) Serve(ctx context.Context) error {
	serveErrors := make(chan error, 1)
	go func() {
		serveErrors <- s.httpServer.Serve(s.listener)
	}()

	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := s.httpServer.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shut down server: %w", err)
		}

		return nil
	}
}

func loadTemplates() (*template.Template, error) {
	templates, err := template.New("report.html").Funcs(template.FuncMap{
		"dict": func(values ...any) map[string]any {
			result := make(map[string]any, len(values)/2)
			for index := 0; index+1 < len(values); index += 2 {
				key, ok := values[index].(string)
				if ok {
					result[key] = values[index+1]
				}
			}

			return result
		},
	}).ParseFS(templateFiles, "templates/report.html")
	if err != nil {
		return nil, fmt.Errorf("parse report template: %w", err)
	}

	return templates, nil
}

// Handler serves reports and health checks.
type Handler struct {
	templates *template.Template
	mux       *http.ServeMux
}

// NewHandler builds the HTTP handler.
func NewHandler(templates *template.Template) http.Handler {
	handler := &Handler{templates: templates}
	handler.mux = http.NewServeMux()
	handler.mux.HandleFunc("GET /", handler.reportHTML)
	handler.mux.HandleFunc("GET /api/v1/report", handler.reportJSON)
	handler.mux.HandleFunc("GET /healthz", handler.health)

	return handler.mux
}

func (h *Handler) reportHTML(writer http.ResponseWriter, request *http.Request) {
	scan, ok := currentReport(request)
	if !ok {
		http.Error(writer, "ClientHello observation is unavailable", http.StatusServiceUnavailable)

		return
	}

	if request.URL.Query().Get("format") == "json" || acceptsJSON(request.Header.Get("Accept")) {
		writeJSON(writer, scan)

		return
	}

	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(writer, "report.html", scan); err != nil {
		http.Error(writer, "Unable to render report", http.StatusInternalServerError)
	}
}

func (h *Handler) reportJSON(writer http.ResponseWriter, request *http.Request) {
	scan, ok := currentReport(request)
	if !ok {
		http.Error(writer, "ClientHello observation is unavailable", http.StatusServiceUnavailable)

		return
	}

	writeJSON(writer, scan)
}

func (h *Handler) health(writer http.ResponseWriter, _ *http.Request) {
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write([]byte(`{"status":"ok"}`))
}

func currentReport(request *http.Request) (report.Report, bool) {
	observation, ok := capture.FromContext(request.Context())
	if !ok || observation == nil {
		return report.Report{}, false
	}

	hello, ok := observation.Get()
	if !ok {
		return report.Report{}, false
	}

	return analyzer.Analyze(hello, request.TLS), true
}

func writeJSON(writer http.ResponseWriter, scan report.Report) {
	writer.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")

	_ = encoder.Encode(scan)
}

func acceptsJSON(accept string) bool {
	for value := range strings.SplitSeq(accept, ",") {
		mediaType := strings.TrimSpace(strings.SplitN(value, ";", 2)[0])
		if mediaType == "application/json" {
			return true
		}
	}

	return false
}
