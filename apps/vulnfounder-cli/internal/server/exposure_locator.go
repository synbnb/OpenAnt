package server

import "net/http"

// handleExposureLocatorIndex renders the unified two-stage OpenHarmony
// workflow. Stage-specific API handlers deliberately remain in their original
// files so existing bookmarks, sessions and clients continue to work.
func (s *Server) handleExposureLocatorIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if s.tmplExposureLocator == nil {
		http.Error(w, "暴露面识别与定位页面未初始化", http.StatusInternalServerError)
		return
	}
	if err := s.tmplExposureLocator.Execute(w, struct{ CSRF string }{CSRF: s.csrfToken}); err != nil {
		http.Error(w, "暴露面识别与定位页面渲染失败", http.StatusInternalServerError)
	}
}
