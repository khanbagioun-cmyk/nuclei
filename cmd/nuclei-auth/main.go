package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/authscan"
)

const banner = `
    _   __           ____            _     ___              
   / | / /___ ______/ __/___  ____  (_)___/ (_)___  ___ 
  /  |/ / __  / ___/ /_/ __ \/ __ \/ / __  / / __ \/ _ \
 / /|  / /_/ (__  ) __/ /_/ / / / / / /_/ / / / / /  __/
/_/ |_/\__,_/____/_/  \____/_/ /_/_/\__,_/_/_/ /_/\___/   
                                                          
              Authenticated Scanning Orchestrator`

func main() {
	var (
		method         string
		loginURL       string
		username       string
		password       string
		token          string
		domain         string
		oauth2ID       string
		oauth2Secret   string
		oauth2TokenURL string
		oauth2Scopes   string
		cookies        string
		headers        string
		timeout        time.Duration
		insecure       bool

		// Scan options
		targets          string
		preAuthTemplates string
		postAuthTemplates string
		outputDir        string
		nucleiBinary     string
		extraFlags       string

		// Actions
		authOnly   bool
		genSecrets string
		discover   bool
		jsonOut    bool
	)

	flag.StringVar(&method, "method", "form", "Auth method: form, basic, bearer, oauth2, cookie, header")
	flag.StringVar(&loginURL, "login-url", "", "Login URL (for form auth)")
	flag.StringVar(&username, "username", "", "Username/email")
	flag.StringVar(&password, "password", "", "Password")
	flag.StringVar(&token, "token", "", "Bearer token")
	flag.StringVar(&domain, "domain", "", "Target domain (required for secrets file)")
	flag.StringVar(&oauth2ID, "oauth2-id", "", "OAuth2 client ID")
	flag.StringVar(&oauth2Secret, "oauth2-secret", "", "OAuth2 client secret")
	flag.StringVar(&oauth2TokenURL, "oauth2-token-url", "", "OAuth2 token endpoint URL")
	flag.StringVar(&oauth2Scopes, "oauth2-scopes", "", "OAuth2 scopes (space-separated)")
	flag.StringVar(&cookies, "cookies", "", "Cookies (format: key1=val1,key2=val2)")
	flag.StringVar(&headers, "headers", "", "Headers (format: Key1:Val1,Key2:Val2)")
	flag.DurationVar(&timeout, "timeout", 15*time.Second, "HTTP timeout")
	flag.BoolVar(&insecure, "insecure", true, "Skip TLS verification")

	flag.StringVar(&targets, "targets", "", "Target URLs (comma-separated)")
	flag.StringVar(&preAuthTemplates, "pre-auth-t", "", "Pre-auth template paths (comma-separated)")
	flag.StringVar(&postAuthTemplates, "post-auth-t", "", "Post-auth template paths (comma-separated)")
	flag.StringVar(&outputDir, "output-dir", "", "Output directory for results")
	flag.StringVar(&nucleiBinary, "nuclei", "nuclei-dev", "Nuclei binary path")
	flag.StringVar(&extraFlags, "extra-flags", "", "Extra nuclei flags")

	flag.BoolVar(&authOnly, "auth-only", false, "Only authenticate and print session info")
	flag.StringVar(&genSecrets, "gen-secrets", "", "Authenticate and generate a nuclei secrets file at the given path")
	flag.BoolVar(&discover, "discover", false, "Discover login form from target URL")
	flag.BoolVar(&jsonOut, "json", false, "Output JSON format")
	flag.Parse()

	if !jsonOut {
		fmt.Println(banner)
	}

	// Discover mode: find login form
	if discover {
		if targets == "" {
			fmt.Fprintln(os.Stderr, "Error: -targets required for discover mode")
			os.Exit(1)
		}
		targetList := strings.Split(targets, ",")
		for _, target := range targetList {
			target = strings.TrimSpace(target)
			cfg, err := authscan.AuthProfileFromURL(target)
			if err != nil {
				if !jsonOut {
					fmt.Printf("[-] %s: no login form found\n", target)
				}
				continue
			}
			if jsonOut {
				b, _ := json.Marshal(cfg)
				fmt.Println(string(b))
			} else {
				fmt.Printf("[+] %s: login form found at %s\n", target, cfg.LoginURL)
			}
		}
		return
	}

	// Build auth config
	cfg := &authscan.AuthConfig{
		Method:             method,
		LoginURL:           loginURL,
		Username:           username,
		Password:           password,
		Token:              token,
		Domain:             domain,
		OAuth2ClientID:     oauth2ID,
		OAuth2ClientSecret: oauth2Secret,
		OAuth2TokenURL:     oauth2TokenURL,
		OAuth2Scopes:       oauth2Scopes,
		Timeout:            timeout,
		InsecureSkipVerify: insecure,
	}

	// Parse cookies
	if cookies != "" {
		for _, c := range strings.Split(cookies, ",") {
			parts := strings.SplitN(c, "=", 2)
			if len(parts) == 2 {
				cfg.Cookies = append(cfg.Cookies, authscan.CookieConfig{
					Key:   strings.TrimSpace(parts[0]),
					Value: strings.TrimSpace(parts[1]),
				})
			}
		}
	}

	// Parse headers
	if headers != "" {
		for _, h := range strings.Split(headers, ",") {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) == 2 {
				cfg.Headers = append(cfg.Headers, authscan.HeaderConfig{
					Key:   strings.TrimSpace(parts[0]),
					Value: strings.TrimSpace(parts[1]),
				})
			}
		}
	}

	// Validate config
	if err := validateConfig(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Create session and authenticate
	session, err := authscan.NewSession(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating session: %v\n", err)
		os.Exit(1)
	}

	if err := session.Authenticate(); err != nil {
		fmt.Fprintf(os.Stderr, "Authentication failed: %v\n", err)
		os.Exit(1)
	}

	// Auth-only mode
	if authOnly {
		info := map[string]interface{}{
			"method":     cfg.Method,
			"domain":     cfg.Domain,
			"expired":    session.IsExpired(),
			"cookies":    len(session.GetCookies()),
			"has_token":  session.GetToken() != "",
		}
		if session.GetToken() != "" {
			info["token"] = session.GetToken()
		}
		if jsonOut {
			b, _ := json.Marshal(info)
			fmt.Println(string(b))
		} else {
			fmt.Printf("[+] Authentication successful (%s)\n", cfg.Method)
			fmt.Printf("    Domain:  %s\n", cfg.Domain)
			fmt.Printf("    Cookies: %d\n", len(session.GetCookies()))
			if session.GetToken() != "" {
				fmt.Printf("    Token:   %s...%s\n", session.GetToken()[:min(10, len(session.GetToken()))], "****")
			}
		}
		return
	}

	// Generate secrets file mode
	if genSecrets != "" {
		if err := authscan.GenerateSecretsFile(session, genSecrets); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating secrets file: %v\n", err)
			os.Exit(1)
		}
		if jsonOut {
			fmt.Printf(`{"secrets_file":"%s","method":"%s"}`+"\n", genSecrets, cfg.Method)
		} else {
			fmt.Printf("[+] Secrets file generated: %s\n", genSecrets)
		}
		return
	}

	// Full scan mode
	if targets == "" {
		fmt.Fprintln(os.Stderr, "Error: -targets required for scan mode (or use -auth-only / -gen-secrets)")
		os.Exit(1)
	}

	scanCfg := &authscan.ScanConfig{
		Targets:           strings.Split(targets, ","),
		PreAuthTemplates:  splitNonEmpty(preAuthTemplates),
		PostAuthTemplates: splitNonEmpty(postAuthTemplates),
		OutputDir:         outputDir,
		NucleiBinary:      nucleiBinary,
		ExtraFlags:        splitNonEmpty(extraFlags),
	}

	orch := authscan.NewOrchestrator(cfg, scanCfg)
	result, err := orch.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		os.Exit(1)
	}

	if jsonOut {
		b, _ := json.Marshal(result)
		fmt.Println(string(b))
	} else {
		fmt.Printf("\n[+] Scan complete (%s)\n", result.Duration)
		fmt.Printf("    Auth:        %s (success: %v)\n", result.AuthMethod, result.AuthSuccess)
		fmt.Printf("    Pre-auth:    %d findings\n", len(result.PreAuthFindings))
		fmt.Printf("    Post-auth:   %d findings\n", len(result.PostAuthFindings))
		if len(result.PreAuthFindings) > 0 {
			fmt.Println("\n  Pre-auth findings:")
			for _, f := range result.PreAuthFindings {
				fmt.Printf("    [%s] %s — %s\n", f.Severity, f.TemplateID, f.Host)
			}
		}
		if len(result.PostAuthFindings) > 0 {
			fmt.Println("\n  Post-auth findings:")
			for _, f := range result.PostAuthFindings {
				fmt.Printf("    [%s] %s — %s\n", f.Severity, f.TemplateID, f.Host)
			}
		}
	}
}

func validateConfig(cfg *authscan.AuthConfig) error {
	if cfg.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	switch strings.ToLower(cfg.Method) {
	case "form":
		if cfg.LoginURL == "" {
			return fmt.Errorf("login-url required for form auth")
		}
		if cfg.Username == "" || cfg.Password == "" {
			return fmt.Errorf("username and password required for form auth")
		}
	case "basic":
		if cfg.Username == "" || cfg.Password == "" {
			return fmt.Errorf("username and password required for basic auth")
		}
	case "bearer":
		if cfg.Token == "" {
			return fmt.Errorf("token required for bearer auth")
		}
	case "oauth2":
		if cfg.OAuth2ClientID == "" || cfg.OAuth2ClientSecret == "" || cfg.OAuth2TokenURL == "" {
			return fmt.Errorf("oauth2-id, oauth2-secret, and oauth2-token-url required for oauth2")
		}
	case "cookie":
		if len(cfg.Cookies) == 0 {
			return fmt.Errorf("cookies required for cookie auth")
		}
	case "header":
		if len(cfg.Headers) == 0 {
			return fmt.Errorf("headers required for header auth")
		}
	default:
		return fmt.Errorf("unsupported method: %s", cfg.Method)
	}
	return nil
}

func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
