/**
 * Session Reconstruction.
 *
 * Groups related flows into logical sessions to enable behavioral analysis
 * and anomaly detection. Sessions represent coherent user activities.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package correlator

import (
	"sync"
	"time"

	"github.com/kleaSCM/netscope/internal/models"
)

// Session represents a group of related flows forming a logical user activity.
type Session struct {
	ID           string
	DeviceMAC    string
	Application  string
	Destination  string // Domain or IP
	StartTime    time.Time
	LastSeen     time.Time
	FlowIDs      []int64
	TotalBytes   uint64
	TotalPackets uint64
	FlowCount    int
}

// SessionTracker manages active sessions and groups flows.
type SessionTracker struct {
	sessions       map[string]*Session // sessionKey -> Session
	sessionTimeout time.Duration
	mu             sync.RWMutex
}

// Creates a new session tracker with configurable timeout.
// Timeout determines when inactive sessions expire (default: 5 minutes).
func NewSessionTracker(timeout time.Duration) *SessionTracker {
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	return &SessionTracker{
		sessions:       make(map[string]*Session),
		sessionTimeout: timeout,
	}
}

// Adds a flow to an appropriate session or creates a new one.
// Sessions are grouped by device + destination + application.
func (st *SessionTracker) TrackFlow(flow *models.Flow) *Session {
	if flow == nil {
		return nil
	}

	// Build session key: device + destination + app
	sessionKey := st.buildSessionKey(flow)

	st.mu.Lock()
	defer st.mu.Unlock()

	// Check if session exists
	if session, ok := st.sessions[sessionKey]; ok {
		// Update existing session
		session.LastSeen = flow.LastSeen
		session.FlowIDs = append(session.FlowIDs, flow.ID)
		session.TotalBytes += flow.ByteCount
		session.TotalPackets += flow.PacketCount
		session.FlowCount++
		return session
	}

	// Create new session
	session := &Session{
		ID:           sessionKey,
		DeviceMAC:    flow.Key.SrcIP,
		Application:  flow.Application,
		Destination:  flow.DstDomain,
		StartTime:    flow.FirstSeen,
		LastSeen:     flow.LastSeen,
		FlowIDs:      []int64{flow.ID},
		TotalBytes:   flow.ByteCount,
		TotalPackets: flow.PacketCount,
		FlowCount:    1,
	}

	if session.Destination == "" {
		session.Destination = flow.Key.DstIP
	}

	st.sessions[sessionKey] = session
	return session
}

// Creates a unique key for session grouping to correlate related flows.
// Groups flows by device, destination domain/IP, and application.
func (st *SessionTracker) buildSessionKey(flow *models.Flow) string {
	device := flow.Key.SrcIP
	dest := flow.DstDomain
	if dest == "" {
		dest = flow.Key.DstIP
	}
	app := flow.Application
	if app == "" {
		app = "unknown"
	}

	return device + "|" + dest + "|" + app
}

// Returns all currently active sessions for analysis and reporting.
func (st *SessionTracker) GetActiveSessions() []*Session {
	st.mu.RLock()
	defer st.mu.RUnlock()

	sessions := make([]*Session, 0, len(st.sessions))
	for _, session := range st.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// Returns all active sessions for a specific device to enable per-device analysis.
func (st *SessionTracker) GetSessionsForDevice(deviceMAC string) []*Session {
	st.mu.RLock()
	defer st.mu.RUnlock()

	sessions := make([]*Session, 0)
	for _, session := range st.sessions {
		if session.DeviceMAC == deviceMAC {
			sessions = append(sessions, session)
		}
	}
	return sessions
}

// Removes sessions that haven't seen activity within the timeout to prevent memory leaks.
// Returns the number of expired sessions.
func (st *SessionTracker) ExpireSessions() int {
	st.mu.Lock()
	defer st.mu.Unlock()

	now := time.Now()
	expired := 0

	for key, session := range st.sessions {
		if now.Sub(session.LastSeen) > st.sessionTimeout {
			delete(st.sessions, key)
			expired++
		}
	}

	return expired
}

// Returns the total number of active sessions for monitoring and metrics.
func (st *SessionTracker) GetSessionCount() int {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return len(st.sessions)
}
