package intelligence

import (
	"sync"
)

// TechProfileSnapshot is a lock-free copy of TechProfile for read-only access
type TechProfileSnapshot struct {
	Host         string
	Technologies []string
	Services     []ServiceInfo
	CMS          string
	Framework    string
	WebServer    string
	Language     string
	OS           string
	PanelPaths   []string
	OpenPorts    []int
}

// TechProfile holds the detected technologies for a single host
type TechProfile struct {
	Host         string
	Technologies []string
	Services     []ServiceInfo
	CMS          string
	Framework    string
	WebServer    string
	Language     string
	OS           string
	PanelPaths   []string
	OpenPorts    []int
	mu           sync.Mutex
}

// ServiceInfo holds a detected service
type ServiceInfo struct {
	Name    string
	Port    int
	Banner  string
	Version string
}

// NewTechProfile creates a new TechProfile for a host
func NewTechProfile(host string) *TechProfile {
	return &TechProfile{
		Host:         host,
		Technologies: []string{},
		Services:     []ServiceInfo{},
		PanelPaths:   []string{},
		OpenPorts:    []int{},
	}
}

// AddTech adds a detected technology (deduplicated)
func (t *TechProfile) AddTech(tech string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, existing := range t.Technologies {
		if existing == tech {
			return
		}
	}
	t.Technologies = append(t.Technologies, tech)
}

// AddService adds a detected service (deduplicated by name+port)
func (t *TechProfile) AddService(svc ServiceInfo) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, existing := range t.Services {
		if existing.Name == svc.Name && existing.Port == svc.Port {
			return
		}
	}
	t.Services = append(t.Services, svc)
}

// AddPanelPath adds a detected admin panel path
func (t *TechProfile) AddPanelPath(path string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, existing := range t.PanelPaths {
		if existing == path {
			return
		}
	}
	t.PanelPaths = append(t.PanelPaths, path)
}

// AddPort adds an open port
func (t *TechProfile) AddPort(port int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, existing := range t.OpenPorts {
		if existing == port {
			return
		}
	}
	t.OpenPorts = append(t.OpenPorts, port)
}

// SetCMS sets the detected CMS
func (t *TechProfile) SetCMS(cms string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.CMS = cms
}

// SetFramework sets the detected framework
func (t *TechProfile) SetFramework(fw string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Framework = fw
}

// SetWebServer sets the detected web server
func (t *TechProfile) SetWebServer(ws string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.WebServer = ws
}

// SetLanguage sets the detected language
func (t *TechProfile) SetLanguage(lang string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Language = lang
}

// HasTech returns true if a technology was detected
func (t *TechProfile) HasTech(tech string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, t := range t.Technologies {
		if t == tech {
			return true
		}
	}
	return false
}

// HasAnyTech returns true if any of the given techs were detected
func (t *TechProfile) HasAnyTech(techs []string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	techSet := make(map[string]bool)
	for _, tech := range t.Technologies {
		techSet[tech] = true
	}
	for _, tech := range techs {
		if techSet[tech] {
			return true
		}
	}
	return false
}

// Snapshot returns a read-only copy of the profile (safe for concurrent reads)
func (t *TechProfile) Snapshot() TechProfileSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	techs := make([]string, len(t.Technologies))
	copy(techs, t.Technologies)
	svcs := make([]ServiceInfo, len(t.Services))
	copy(svcs, t.Services)
	panels := make([]string, len(t.PanelPaths))
	copy(panels, t.PanelPaths)
	ports := make([]int, len(t.OpenPorts))
	copy(ports, t.OpenPorts)
	return TechProfileSnapshot{
		Host:         t.Host,
		Technologies: techs,
		Services:     svcs,
		CMS:          t.CMS,
		Framework:    t.Framework,
		WebServer:    t.WebServer,
		Language:     t.Language,
		OS:           t.OS,
		PanelPaths:   panels,
		OpenPorts:    ports,
	}
}

// ProfileStore holds TechProfiles for multiple hosts
type ProfileStore struct {
	profiles sync.Map // map[string]*TechProfile
}

// NewProfileStore creates a new ProfileStore
func NewProfileStore() *ProfileStore {
	return &ProfileStore{}
}

// GetOrCreate returns the TechProfile for a host, creating it if needed
func (ps *ProfileStore) GetOrCreate(host string) *TechProfile {
	val, _ := ps.profiles.LoadOrStore(host, NewTechProfile(host))
	return val.(*TechProfile)
}

// Get returns the TechProfile for a host, or nil if not found
func (ps *ProfileStore) Get(host string) *TechProfile {
	val, ok := ps.profiles.Load(host)
	if !ok {
		return nil
	}
	return val.(*TechProfile)
}

// All returns all profiles
func (ps *ProfileStore) All() []*TechProfile {
	var profiles []*TechProfile
	ps.profiles.Range(func(_, val interface{}) bool {
		profiles = append(profiles, val.(*TechProfile))
		return true
	})
	return profiles
}

// Count returns the number of profiles
func (ps *ProfileStore) Count() int {
	count := 0
	ps.profiles.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}
