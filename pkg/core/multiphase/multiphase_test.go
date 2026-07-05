package multiphase

import (
	"testing"
)

func TestTechProfile(t *testing.T) {
	tp := NewTechProfile()
	tp.Add("WordPress")
	tp.Add("wordpress")
	tp.Add("Nginx")

	if !tp.Has("wordpress") {
		t.Error("expected wordpress to be present (case-insensitive)")
	}
	if !tp.Has("NGINX") {
		t.Error("expected NGINX to be present (case-insensitive)")
	}
	if tp.Has("Apache") {
		t.Error("Apache should not be present")
	}

	all := tp.All()
	if len(all) != 2 {
		t.Errorf("expected 2 distinct techs, got %d", len(all))
	}
}

func TestIsTechTag(t *testing.T) {
	tests := []struct {
		tag    string
		expect bool
	}{
		{"wordpress", true},
		{"nginx", true},
		{"apache", true},
		{"cve", false},
		{"kev", false},
		{"xss", false},
		{"sqli", false},
		{"detect", false},
		{"tech", false},
		{"fingerprint", false},
		{"exposure", false},
		{"tomcat", true},
		{"jenkins", true},
	}
	for _, tt := range tests {
		if got := isTechTag(tt.tag); got != tt.expect {
			t.Errorf("isTechTag(%q) = %v, want %v", tt.tag, got, tt.expect)
		}
	}
}

func TestBuildPhase2Tags(t *testing.T) {
	mpe := &MultiPhaseEngine{
		techProfile: NewTechProfile(),
	}
	mpe.techProfile.Add("wordpress")
	mpe.techProfile.Add("nginx")

	tags := mpe.buildPhase2Tags()

	// Should contain tech tags + priority tags
	hasWP := false
	hasNginx := false
	hasKEV := false
	for _, t := range tags {
		if t == "wordpress" {
			hasWP = true
		}
		if t == "nginx" {
			hasNginx = true
		}
		if t == "kev" {
			hasKEV = true
		}
	}
	if !hasWP {
		t.Error("expected wordpress tag")
	}
	if !hasNginx {
		t.Error("expected nginx tag")
	}
	if !hasKEV {
		t.Error("expected kev priority tag")
	}
}
