// Package api provides the threatlib HTTP server.
package api

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/jayelbotvibe-web/threatlib/internal/store"
)

// Server holds the HTTP server dependencies.
type Server struct {
	DB  *store.DB
	Mux *http.ServeMux
}

// NewServer creates an HTTP server for the threatlib API.
func NewServer(db *store.DB) *Server {
	s := &Server{
		DB:  db,
		Mux: http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

// ListenAndServe starts the HTTP server.
func (s *Server) ListenAndServe(addr string) error {
	log.Printf("api: listening on %s", addr)
	return http.ListenAndServe(addr, s.Mux)
}

func (s *Server) registerRoutes() {
	s.Mux.HandleFunc("/health", s.handleHealth)
	s.Mux.HandleFunc("/api/alerts", s.handleAlerts)
	s.Mux.HandleFunc("/api/techstack", s.handleTechStack)
	s.Mux.HandleFunc("/api/stats", s.handleStats)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	var alertCount, deadLetterCount int
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM alerts").Scan(&alertCount)
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM dedup_hashes").Scan(&deadLetterCount)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":            "ok",
		"alerts_total":      alertCount,
		"dedup_entries":     deadLetterCount,
	})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Conn().Query(
		`SELECT id, event_id, severity, confidence, status, matched_apps, created_at
		 FROM alerts ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer rows.Close()

	type alertRow struct {
		ID          string `json:"id"`
		EventID     string `json:"event_id"`
		Severity    string `json:"severity"`
		Confidence  string `json:"confidence"`
		Status      string `json:"status"`
		MatchedApps string `json:"matched_apps"`
		CreatedAt   string `json:"created_at"`
	}

	var alerts []alertRow
	for rows.Next() {
		var a alertRow
		if err := rows.Scan(&a.ID, &a.EventID, &a.Severity, &a.Confidence, &a.Status, &a.MatchedApps, &a.CreatedAt); err != nil {
			continue
		}
		alerts = append(alerts, a)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alerts": alerts,
		"count":  len(alerts),
	})
}

func (s *Server) handleTechStack(w http.ResponseWriter, r *http.Request) {
	apps, err := s.DB.ListTechStack()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	type appSummary struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		Criticality string `json:"criticality"`
		Internet    bool   `json:"internet_facing"`
	}

	var list []appSummary
	for _, a := range apps {
		list = append(list, appSummary{
			Name:        a.Name,
			Version:     a.Version,
			Criticality: a.Criticality,
			Internet:    a.InternetFacing,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"apps":  list,
		"count": len(list),
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	var total, critical, high, medium, low int

	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM alerts").Scan(&total)
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM alerts WHERE severity='critical'").Scan(&critical)
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM alerts WHERE severity='high'").Scan(&high)
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM alerts WHERE severity='medium'").Scan(&medium)
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM alerts WHERE severity='low'").Scan(&low)

	var eventCount int
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM events").Scan(&eventCount)

	var appCount int
	s.DB.Conn().QueryRow("SELECT COUNT(*) FROM tech_stack").Scan(&appCount)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"alerts": map[string]int{
			"total":    total,
			"critical": critical,
			"high":     high,
			"medium":   medium,
			"low":      low,
		},
		"events_stored": eventCount,
		"apps_tracked":  appCount,
	})
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
