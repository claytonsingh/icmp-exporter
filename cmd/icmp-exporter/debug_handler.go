package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"time"
)

// DebugProbesHandler dumps all probe targets and their statistics
func DebugProbesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	probes := make([]map[string]any, 0)

	probeMap.Range(func(key any, value any) bool {
		if probe, ok := value.(*PingProbe); ok {
			probe.Mutex.Lock()
			probeInfo := map[string]any{
				"ip_address":  probe.IPAddress.String(),
				"tcp_port":    probe.TCPPort,
				"sent_count":  probe.SentCount,
				"recv_count":  probe.RecvCount,
				"last_access": probe.LastAccess.Unix(),
			}

			probe.Mutex.Unlock()
			probes = append(probes, probeInfo)
		}
		return true
	})

	// Sort probes by IP address, then by TCP port for consistent output
	sort.Slice(probes, func(i, j int) bool {
		ipI := probes[i]["ip_address"].(string)
		ipJ := probes[j]["ip_address"].(string)
		if ipI != ipJ {
			return ipI < ipJ
		}
		// If IPs are equal, sort by TCP port
		portI := 0
		portJ := 0
		if v, ok := probes[i]["tcp_port"].(int); ok {
			portI = v
		}
		if v, ok := probes[j]["tcp_port"].(int); ok {
			portJ = v
		}
		return portI < portJ
	})

	response := map[string]any{
		"timestamp":    time.Now().Unix(),
		"total_probes": len(probes),
		"probes":       probes,
	}

	jsonData, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		http.Error(w, "Failed to marshal JSON", http.StatusInternalServerError)
		return
	}

	w.Write(jsonData)
}
