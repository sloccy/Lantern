package proxy

import (
	"compress/gzip"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

// minCompressSize is the smallest response worth compressing when the backend
// states its length up front.
const minCompressSize = 1024

var gzipPool = sync.Pool{New: func() any {
	gz, _ := gzip.NewWriterLevel(nil, gzip.DefaultCompression)
	return gz
}}

// wantsGzip reports whether the client accepts gzip (honoring q=0).
func wantsGzip(r *http.Request) bool {
	for part := range strings.SplitSeq(r.Header.Get("Accept-Encoding"), ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(name), "gzip") && strings.TrimSpace(name) != "*" {
			continue
		}
		if q, ok := strings.CutPrefix(strings.ReplaceAll(strings.TrimSpace(params), " ", ""), "q="); ok {
			if v, err := strconv.ParseFloat(q, 64); err == nil && v == 0 {
				return false
			}
		}
		return true
	}
	return false
}

// compressible reports whether a Content-Type is worth gzipping. Streams
// (text/event-stream) and already-compressed formats are not.
func compressible(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	switch {
	case mt == "text/event-stream":
		return false
	case strings.HasPrefix(mt, "text/"):
		return true
	case strings.HasSuffix(mt, "+json"), strings.HasSuffix(mt, "+xml"):
		return true
	}
	switch mt {
	case "application/json", "application/javascript", "application/x-javascript",
		"application/xml", "application/wasm", "application/x-ndjson", "image/svg+xml":
		return true
	}
	return false
}

// compressResponse wraps w so that eligible responses are gzipped. Call the
// returned func when the handler returns. When the request or response is not
// eligible it passes everything through untouched.
func compressResponse(w http.ResponseWriter, r *http.Request) (out http.ResponseWriter, done func()) {
	if r.Method == http.MethodHead || r.Header.Get("Upgrade") != "" || r.Header.Get("Range") != "" || !wantsGzip(r) {
		return w, func() {}
	}
	cw := &compressWriter{ResponseWriter: w}
	return cw, cw.close
}

type compressWriter struct {
	http.ResponseWriter
	gz          *gzip.Writer
	wroteHeader bool
}

// Unwrap lets http.ResponseController reach the underlying writer (Hijack for
// WebSocket upgrades, deadlines).
func (c *compressWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

func (c *compressWriter) shouldCompress(code int, h http.Header) bool {
	switch {
	case code < 200, code == http.StatusNoContent, code == http.StatusPartialContent, code == http.StatusNotModified:
		return false
	case h.Get("Content-Encoding") != "", h.Get("Content-Range") != "":
		return false
	case strings.Contains(strings.ToLower(h.Get("Cache-Control")), "no-transform"):
		return false
	case !compressible(h.Get("Content-Type")):
		return false
	}
	if cl := h.Get("Content-Length"); cl != "" {
		if n, err := strconv.ParseInt(cl, 10, 64); err == nil && n < minCompressSize {
			return false
		}
	}
	return true
}

func (c *compressWriter) WriteHeader(code int) {
	if c.wroteHeader {
		return
	}
	c.wroteHeader = true
	h := c.Header()
	if code >= 200 && compressible(h.Get("Content-Type")) {
		h.Add("Vary", "Accept-Encoding")
	}
	if c.shouldCompress(code, h) {
		if gz, ok := gzipPool.Get().(*gzip.Writer); ok {
			gz.Reset(c.ResponseWriter)
			c.gz = gz
			h.Set("Content-Encoding", "gzip")
			h.Del("Content-Length")
			if etag := h.Get("ETag"); etag != "" && !strings.HasPrefix(etag, "W/") {
				h.Set("ETag", "W/"+etag)
			}
		}
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *compressWriter) Write(b []byte) (int, error) {
	if !c.wroteHeader {
		c.WriteHeader(http.StatusOK)
	}
	if c.gz != nil {
		return c.gz.Write(b)
	}
	return c.ResponseWriter.Write(b)
}

// Flush pushes buffered data to the client so streaming responses stay live.
func (c *compressWriter) Flush() {
	if c.gz != nil {
		_ = c.gz.Flush()
	}
	_ = http.NewResponseController(c.ResponseWriter).Flush()
}

func (c *compressWriter) close() {
	if c.gz != nil {
		_ = c.gz.Close()
		gzipPool.Put(c.gz)
		c.gz = nil
	}
}
