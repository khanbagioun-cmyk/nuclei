package multiphase

import (
	"strings"
	"sync"
)

// TechProfile holds detected technologies from phase 1.
type TechProfile struct {
	mu    sync.Mutex
	techs map[string]bool
}

func NewTechProfile() *TechProfile {
	return &TechProfile{techs: make(map[string]bool)}
}

func (t *TechProfile) Add(tech string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.techs[strings.ToLower(tech)] = true
}

func (t *TechProfile) Has(tech string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.techs[strings.ToLower(tech)]
}

func (t *TechProfile) All() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]string, 0, len(t.techs))
	for t := range t.techs {
		result = append(result, t)
	}
	return result
}

// IsTechTag returns true if a tag likely represents a detected technology.
func IsTechTag(tag string) bool {
	lower := strings.ToLower(tag)
	nonTech := map[string]bool{
		"cve": true, "kev": true, "vkev": true, "exploit": true,
		"xss": true, "sqli": true, "rce": true, "lfi": true,
		"ssrf": true, "csrf": true, "dos": true, "fuzz": true,
		"bruteforce": true, "detect": true, "tech": true,
		"fingerprint": true, "exposure": true, "misconfig": true,
		"login": true, "auth": true, "default-login": true,
		"oast": true, "intrusive": true, "safe": true,
		"local": true, "txt-service": true,
	}
	if nonTech[lower] {
		return false
	}
	return true
}
