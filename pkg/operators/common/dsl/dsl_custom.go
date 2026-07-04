package dsl

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/projectdiscovery/dsl"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/versionutil"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/wafevasion"
)

// init_custom registers custom DSL functions added by the fork.
// These extend nuclei's YAML matcher/extractor language with:
//   - jwt_decode: decode JWT header/payload without verification
//   - jwt_verify: verify HS256 JWT signature
//   - base64url_decode: URL-safe base64 decode
//   - base64url_encode: URL-safe base64 encode
//   - cidr_contains: check if IP is within CIDR range
//   - regex_extract_all: extract all regex matches as comma-joined string
//   - json_path: extract value at JSON path (dot notation)
//   - json_path_all: extract all values at JSON path (dot notation)
//   - contains_cidr: check if a string contains an IP in a CIDR
func init() {
	// jwt_decode extracts the header or payload from a JWT without verifying signature.
	// Usage: jwt_decode(token, "header"|"payload")
	_ = dsl.AddFunction(dsl.NewWithMultipleSignatures("jwt_decode", []string{
		"(token string, part string) string",
	}, false, func(args ...interface{}) (interface{}, error) {
		if len(args) != 2 {
			return nil, dsl.ErrInvalidDslFunction
		}
		token := types.ToString(args[0])
		part := strings.ToLower(types.ToString(args[1]))

		parts := strings.Split(token, ".")
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid JWT: expected at least 2 parts, got %d", len(parts))
		}

		var segment string
		switch part {
		case "header":
			segment = parts[0]
		case "payload", "body", "claims":
			segment = parts[1]
		default:
			return nil, fmt.Errorf("invalid part: %s (expected 'header' or 'payload')", part)
		}

		decoded, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			return nil, fmt.Errorf("base64url decode failed: %w", err)
		}

		return string(decoded), nil
	}))

	// jwt_verify verifies an HS256 JWT signature against a secret.
	// Usage: jwt_verify(token, secret) bool
	_ = dsl.AddFunction(dsl.NewWithMultipleSignatures("jwt_verify", []string{
		"(token string, secret string) bool",
	}, false, func(args ...interface{}) (interface{}, error) {
		if len(args) != 2 {
			return nil, dsl.ErrInvalidDslFunction
		}
		token := types.ToString(args[0])
		secret := types.ToString(args[1])

		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			return false, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
		}

		signedContent := parts[0] + "." + parts[1]
		signature := parts[2]

		expectedSig, err := hmacSHA256Base64URL(signedContent, secret)
		if err != nil {
			return false, err
		}

		return signature == expectedSig, nil
	}))

	// base64url_decode decodes a URL-safe base64 string.
	// Usage: base64url_decode(s) string
	_ = dsl.AddFunction(dsl.NewWithMultipleSignatures("base64url_decode", []string{
		"(s string) string",
	}, false, func(args ...interface{}) (interface{}, error) {
		if len(args) != 1 {
			return nil, dsl.ErrInvalidDslFunction
		}
		s := types.ToString(args[0])
		decoded, err := base64.URLEncoding.DecodeString(s)
		if err != nil {
			decoded, err = base64.RawURLEncoding.DecodeString(s)
			if err != nil {
				return nil, fmt.Errorf("base64url decode failed: %w", err)
			}
		}
		return string(decoded), nil
	}))

	// base64url_encode encodes a string to URL-safe base64.
	// Usage: base64url_encode(s) string
	_ = dsl.AddFunction(dsl.NewWithMultipleSignatures("base64url_encode", []string{
		"(s string) string",
	}, false, func(args ...interface{}) (interface{}, error) {
		if len(args) != 1 {
			return nil, dsl.ErrInvalidDslFunction
		}
		s := types.ToString(args[0])
		return base64.URLEncoding.EncodeToString([]byte(s)), nil
	}))

	// cidr_contains checks if an IP address is within a CIDR range.
	// Usage: cidr_contains(cidr string, ip string) bool
	_ = dsl.AddFunction(dsl.NewWithMultipleSignatures("cidr_contains", []string{
		"(cidr string, ip string) bool",
	}, false, func(args ...interface{}) (interface{}, error) {
		if len(args) != 2 {
			return nil, dsl.ErrInvalidDslFunction
		}
		cidrStr := types.ToString(args[0])
		ipStr := types.ToString(args[1])

		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidrStr, err)
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP %q", ipStr)
		}
		return ipNet.Contains(ip), nil
	}))

	// regex_extract_all extracts all regex matches and joins them with comma.
	// Usage: regex_extract_all(pattern string, input string) string
	_ = dsl.AddFunction(dsl.NewWithMultipleSignatures("regex_extract_all", []string{
		"(pattern string, input string) string",
	}, false, func(args ...interface{}) (interface{}, error) {
		if len(args) != 2 {
			return nil, dsl.ErrInvalidDslFunction
		}
		patternStr := types.ToString(args[0])
		input := types.ToString(args[1])

		re, err := regexp.Compile(patternStr)
		if err != nil {
			return nil, fmt.Errorf("invalid regex %q: %w", patternStr, err)
		}
		matches := re.FindAllString(input, -1)
		if len(matches) == 0 {
			return "", nil
		}
		return strings.Join(matches, ","), nil
	}))

	// json_path extracts a value at a dot-notation path from a JSON string.
	// Usage: json_path(json string, path string) string
	// Example: json_path(body, "data.user.email")
	_ = dsl.AddFunction(dsl.NewWithMultipleSignatures("json_path", []string{
		"(json string, path string) string",
	}, false, func(args ...interface{}) (interface{}, error) {
		if len(args) != 2 {
			return nil, dsl.ErrInvalidDslFunction
		}
		jsonStr := types.ToString(args[0])
		path := types.ToString(args[1])

		var data interface{}
		if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
			return nil, fmt.Errorf("json parse failed: %w", err)
		}

		keys := strings.Split(path, ".")
		current := data
		for _, key := range keys {
			m, ok := current.(map[string]interface{})
			if !ok {
				return "", nil
			}
			current, ok = m[key]
			if !ok {
				return "", nil
			}
		}
		return types.ToString(current), nil
	}))

	// json_path_all extracts all values matching a key at any depth in JSON.
	// Usage: json_path_all(json string, key string) string
	// Returns comma-joined values.
	_ = dsl.AddFunction(dsl.NewWithMultipleSignatures("json_path_all", []string{
		"(json string, key string) string",
	}, false, func(args ...interface{}) (interface{}, error) {
		if len(args) != 2 {
			return nil, dsl.ErrInvalidDslFunction
		}
		jsonStr := types.ToString(args[0])
		key := types.ToString(args[1])

		var data interface{}
		if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
			return nil, fmt.Errorf("json parse failed: %w", err)
		}

		var results []string
		collectByKey(data, key, &results)
		if len(results) == 0 {
			return "", nil
		}
		return strings.Join(results, ","), nil
	}))

	// waf_encode_hex: URL-hex-encode special chars in a payload
	// Usage: waf_encode_hex("1' OR 1=1--")
	dsl.AddFunction(dsl.NewWithSingleSignature("waf_encode_hex", "(s string) string", false, func(args ...interface{}) (interface{}, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("waf_encode_hex requires 1 argument")
		}
		return wafevasion.URLHexEncodeFn(types.ToString(args[0])), nil
	}))

	// waf_sqli_variants: generate SQLi evasion variants (returns first variant)
	// Usage: waf_sqli_variants("UNION SELECT")
	dsl.AddFunction(dsl.NewWithSingleSignature("waf_sqli_variants", "(s string) string", false, func(args ...interface{}) (interface{}, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("waf_sqli_variants requires 1 argument")
		}
		variants := wafevasion.GenerateSQLiVariants(types.ToString(args[0]))
		if len(variants) > 1 {
			return variants[1], nil
		}
		return types.ToString(args[0]), nil
	}))

	// waf_xss_variants: generate XSS evasion variants (returns first variant)
	dsl.AddFunction(dsl.NewWithSingleSignature("waf_xss_variants", "(s string) string", false, func(args ...interface{}) (interface{}, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("waf_xss_variants requires 1 argument")
		}
		variants := wafevasion.GenerateXSSVariants(types.ToString(args[0]))
		if len(variants) > 1 {
			return variants[1], nil
		}
		return types.ToString(args[0]), nil
	}))

	// waf_random_ua: returns a random User-Agent string
	dsl.AddFunction(dsl.NewWithSingleSignature("waf_random_ua", "() string", false, func(args ...interface{}) (interface{}, error) {
		return wafevasion.RandomUserAgent(), nil
	}))

	// waf_random_xff: returns a random X-Forwarded-For IP
	dsl.AddFunction(dsl.NewWithSingleSignature("waf_random_xff", "() string", false, func(args ...interface{}) (interface{}, error) {
		return wafevasion.RandomXForwardedFor(), nil
	}))

	// version_compare compares two version strings.
	// Returns: -1 if a < b, 0 if a == b, 1 if a > b
	// Usage: version_compare("1.2.3", "1.2.4") -> -1
	dsl.AddFunction(dsl.NewWithSingleSignature("version_compare", "(a string, b string) float64", false, func(args ...interface{}) (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("version_compare requires 2 arguments")
		}
		return float64(versionutil.CompareStrings(types.ToString(args[0]), types.ToString(args[1]))), nil
	}))

	// version_in_range checks if a version falls within [from, to).
	// Usage: version_in_range(detected, "1.0.0", "2.0.0") -> true if detected is >= 1.0.0 and < 2.0.0
	dsl.AddFunction(dsl.NewWithSingleSignature("version_in_range", "(version string, from string, to string) bool", false, func(args ...interface{}) (interface{}, error) {
		if len(args) < 3 {
			return nil, fmt.Errorf("version_in_range requires 3 arguments")
		}
		return versionutil.InRangeStrings(types.ToString(args[0]), types.ToString(args[1]), types.ToString(args[2])), nil
	}))

	// version_lt checks if version a is less than version b.
	// Usage: version_lt("1.2.3", "2.0.0") -> true
	dsl.AddFunction(dsl.NewWithSingleSignature("version_lt", "(a string, b string) bool", false, func(args ...interface{}) (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("version_lt requires 2 arguments")
		}
		return versionutil.CompareStrings(types.ToString(args[0]), types.ToString(args[1])) < 0, nil
	}))

	// version_ge checks if version a is greater than or equal to version b.
	// Usage: version_ge("2.0.0", "1.2.3") -> true
	dsl.AddFunction(dsl.NewWithSingleSignature("version_ge", "(a string, b string) bool", false, func(args ...interface{}) (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("version_ge requires 2 arguments")
		}
		return versionutil.CompareStrings(types.ToString(args[0]), types.ToString(args[1])) >= 0, nil
	}))

	// version_eq checks if two versions are equal.
	// Usage: version_eq("1.2.3", "1.2.3") -> true
	dsl.AddFunction(dsl.NewWithSingleSignature("version_eq", "(a string, b string) bool", false, func(args ...interface{}) (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("version_eq requires 2 arguments")
		}
		return versionutil.CompareStrings(types.ToString(args[0]), types.ToString(args[1])) == 0, nil
	}))

	// version_ne checks if two versions are not equal.
	// Usage: version_ne("1.2.3", "2.0.0") -> true
	dsl.AddFunction(dsl.NewWithSingleSignature("version_ne", "(a string, b string) bool", false, func(args ...interface{}) (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("version_ne requires 2 arguments")
		}
		return versionutil.CompareStrings(types.ToString(args[0]), types.ToString(args[1])) != 0, nil
	}))

	// version_le checks if version a is less than or equal to version b.
	// Usage: version_le("1.2.3", "2.0.0") -> true
	dsl.AddFunction(dsl.NewWithSingleSignature("version_le", "(a string, b string) bool", false, func(args ...interface{}) (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("version_le requires 2 arguments")
		}
		return versionutil.CompareStrings(types.ToString(args[0]), types.ToString(args[1])) <= 0, nil
	}))

	// version_gt checks if version a is greater than version b.
	// Usage: version_gt("2.0.0", "1.2.3") -> true
	dsl.AddFunction(dsl.NewWithSingleSignature("version_gt", "(a string, b string) bool", false, func(args ...interface{}) (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("version_gt requires 2 arguments")
		}
		return versionutil.CompareStrings(types.ToString(args[0]), types.ToString(args[1])) > 0, nil
	}))

	// Populate helper function maps AFTER all custom functions are registered.
	// This ensures version_compare, version_in_range, etc. are available to
	// the template compiler.
	initHelperFunctions()
}

// collectByKey recursively walks a JSON structure collecting all values
// for the given key.
func collectByKey(data interface{}, key string, results *[]string) {
	switch v := data.(type) {
	case map[string]interface{}:
		for k, val := range v {
			if k == key {
				*results = append(*results, types.ToString(val))
			}
			collectByKey(val, key, results)
		}
	case []interface{}:
		for _, item := range v {
			collectByKey(item, key, results)
		}
	}
}

// hmacSHA256Base64URL computes HMAC-SHA256 of data using secret,
// returns URL-safe base64 encoding (no padding).
func hmacSHA256Base64URL(data, secret string) (string, error) {
	h := hmac.New(sha256.New, []byte(secret))
	if _, err := h.Write([]byte(data)); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}
