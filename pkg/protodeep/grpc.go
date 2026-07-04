package protodeep

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// GRPCScanner performs gRPC reflection and health checks
type GRPCScanner struct {
	timeout time.Duration
}

// GRPCConfig configures the gRPC scanner
type GRPCConfig struct {
	Timeout time.Duration
}

// DefaultGRPCConfig returns sensible defaults
func DefaultGRPCConfig() GRPCConfig {
	return GRPCConfig{Timeout: 10 * time.Second}
}

// NewGRPCScanner creates a new gRPC scanner
func NewGRPCScanner(config GRPCConfig) *GRPCScanner {
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	return &GRPCScanner{timeout: config.Timeout}
}

// GRPCResult holds the gRPC scan result
type GRPCResult struct {
	Target          string          `json:"target"`
	ReflectionEnabled bool          `json:"reflection_enabled"`
	Services        []GRPCService   `json:"services,omitempty"`
	HealthStatus    string          `json:"health_status,omitempty"`
	HealthChecked   bool            `json:"health_checked"`
	Error           string          `json:"error,omitempty"`
}

// GRPCService represents a gRPC service
type GRPCService struct {
	Name     string   `json:"name"`
	Methods  []string `json:"methods,omitempty"`
	File     string   `json:"file,omitempty"`
}

// gRPC reflection uses HTTP/2 with the grpc-reflection protocol.
// Since we don't have google.golang.org/grpc as a dependency,
// we use raw HTTP/2 via Go's net/http with H2C (cleartext).

// reflectionRequest is a ServerReflectionRequest in protobuf wire format
// We construct a minimal request to list all services.
// ServerReflectionRequest { file_by_filename: "" } or { list_services: "" }

// Scan performs gRPC reflection scan
func (s *GRPCScanner) Scan(ctx context.Context, target string, useTLS bool) (*GRPCResult, error) {
	result := &GRPCResult{Target: target}

	// Try reflection via HTTP/2
	services, err := s.reflectServices(ctx, target, useTLS)
	if err != nil {
		result.Error = fmt.Sprintf("reflection failed: %v", err)
		// Still try health check
	} else if len(services) > 0 {
		result.ReflectionEnabled = true
		result.Services = services
		// For each service, try to enumerate methods via file_containing_symbol
		for i := range result.Services {
			methods, mErr := s.reflectMethods(ctx, target, useTLS, result.Services[i].Name)
			if mErr == nil && len(methods) > 0 {
				result.Services[i].Methods = methods
			}
		}
	}

	// Try health check
	healthStatus, ok := s.checkHealth(ctx, target, useTLS)
	result.HealthChecked = ok
	if ok {
		result.HealthStatus = healthStatus
	}

	if !result.ReflectionEnabled && !result.HealthChecked {
		if result.Error == "" {
			result.Error = "gRPC server did not respond to reflection or health check"
		}
	}

	return result, nil
}

// reflectServices attempts gRPC server reflection via HTTP/2
func (s *GRPCScanner) reflectServices(ctx context.Context, target string, useTLS bool) ([]GRPCService, error) {
	// gRPC reflection uses the grpc.reflection.v1alpha.ServerReflection service
	// We send a ServerReflectionRequest with list_services: ""
	// The response is a ServerReflectionResponse with list_services_response

	// Build minimal protobuf message for ServerReflectionRequest:
	// message ServerReflectionRequest {
	//   string host = 1;
	//   oneof message_request {
	//     string file_by_filename = 3;
	//     string file_containing_symbol = 4;
	//     ExtensionRequest file_containing_extension = 5;
	//     ExtensionRequest all_extension_numbers_of_type = 6;
	//     string list_services = 7;  // empty string = list all
	//   }
	// }

	// Protobuf encoding: field 7 (list_services), wire type 2 (length-delimited)
	// Tag = (7 << 3) | 2 = 58
	// Value = empty string (length 0)
	reqBody := []byte{58, 0} // field 7, length 0

	// Build gRPC frame: 1 byte compression flag (0) + 4 byte length + message
	frame := make([]byte, 5+len(reqBody))
	frame[0] = 0 // no compression
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(reqBody)))
	copy(frame[5:], reqBody)

	// Send via HTTP/2 POST to /grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo
	scheme := "https"
	if !useTLS {
		scheme = "http"
	}
	url := fmt.Sprintf("%s://%s/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", scheme, target)

	client := &http.Client{
		Timeout: s.timeout,
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(frame)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")

	// For H2C (cleartext HTTP/2), Go's default transport handles this
	// but we need to set the transport to allow H2C
	if !useTLS {
		client.Transport = &http.Transport{
			DialContext: (&net.Dialer{Timeout: s.timeout}).DialContext,
			ForceAttemptHTTP2: true,
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("gRPC status: %d", resp.StatusCode)
	}

	// Read the gRPC response frame
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(respBody) < 5 {
		return nil, fmt.Errorf("response too short")
	}

	// Parse gRPC frame: 1 byte compressed + 4 byte length + message
	msgLen := binary.BigEndian.Uint32(respBody[1:5])
	if int(msgLen)+5 > len(respBody) {
		return nil, fmt.Errorf("incomplete gRPC frame")
	}
	msg := respBody[5 : 5+msgLen]

	// Parse the protobuf ServerReflectionResponse
	// We're looking for field 7 (list_services_response)
	// list_services_response contains repeated ServiceResponse
	// ServiceResponse { string name = 1; }
	services := s.parseReflectionResponse(msg)

	return services, nil
}

// parseReflectionResponse extracts service names from a ServerReflectionResponse
func (s *GRPCScanner) parseReflectionResponse(msg []byte) []GRPCService {
	var services []GRPCService
	pos := 0

	for pos < len(msg) {
		if pos >= len(msg) {
			break
		}
		tag := msg[pos]
		pos++
		wireType := tag & 0x07
		fieldNum := tag >> 3

		if wireType == 2 { // length-delimited
			if pos >= len(msg) {
				break
			}
			length, n := readVarint(msg[pos:])
			pos += n
			if pos+int(length) > len(msg) {
				break
			}
			value := msg[pos : pos+int(length)]
			pos += int(length)

			if fieldNum == 7 { // list_services_response
				// Parse ServiceResponse entries inside
				services = append(services, s.parseServiceResponse(value)...)
			}
		} else if wireType == 0 { // varint
			_, n := readVarint(msg[pos:])
			pos += n
		} else if wireType == 5 { // 32-bit
			pos += 4
		} else if wireType == 1 { // 64-bit
			pos += 8
		}
	}

	return services
}

// parseServiceResponse extracts service names from a ListServiceResponse
func (s *GRPCScanner) parseServiceResponse(msg []byte) []GRPCService {
	var services []GRPCService
	pos := 0

	for pos < len(msg) {
		tag := msg[pos]
		pos++
		wireType := tag & 0x07
		fieldNum := tag >> 3

		if wireType == 2 && fieldNum == 1 { // ServiceResponse
			length, n := readVarint(msg[pos:])
			pos += n
			if pos+int(length) > len(msg) {
				break
			}
			value := msg[pos : pos+int(length)]
			pos += int(length)

			// Parse ServiceResponse for name (field 1)
			svc := s.parseServiceName(value)
			if svc.Name != "" {
				services = append(services, svc)
			}
		} else if wireType == 0 {
			_, n := readVarint(msg[pos:])
			pos += n
		} else if wireType == 5 {
			pos += 4
		} else if wireType == 1 {
			pos += 8
		} else if wireType == 2 {
			length, n := readVarint(msg[pos:])
			pos += n
			pos += int(length)
		}
	}

	return services
}

// parseServiceName extracts the name from a ServiceResponse message
func (s *GRPCScanner) parseServiceName(msg []byte) GRPCService {
	svc := GRPCService{}
	pos := 0

	for pos < len(msg) {
		tag := msg[pos]
		pos++
		wireType := tag & 0x07
		fieldNum := tag >> 3

		if wireType == 2 && fieldNum == 1 { // name
			length, n := readVarint(msg[pos:])
			pos += n
			if pos+int(length) > len(msg) {
				break
			}
			svc.Name = string(msg[pos : pos+int(length)])
			pos += int(length)
		} else if wireType == 0 {
			_, n := readVarint(msg[pos:])
			pos += n
		} else if wireType == 5 {
			pos += 4
		} else if wireType == 1 {
			pos += 8
		} else if wireType == 2 {
			length, n := readVarint(msg[pos:])
			pos += n
			pos += int(length)
		}
	}

	return svc
}

// checkHealth calls the gRPC health check service
func (s *GRPCScanner) checkHealth(ctx context.Context, target string, useTLS bool) (string, bool) {
	// grpc.health.v1.Health/Check
	// Request: empty message (HealthCheckRequest {})
	// Response: { int32 status = 1; } where 1=SERVING, 2=NOT_SERVING, 3=UNKNOWN

	// Empty protobuf message = no bytes
	frame := make([]byte, 5)
	frame[0] = 0
	binary.BigEndian.PutUint32(frame[1:5], 0)

	scheme := "https"
	if !useTLS {
		scheme = "http"
	}
	url := fmt.Sprintf("%s://%s/grpc.health.v1.Health/Check", scheme, target)

	client := &http.Client{Timeout: s.timeout}
	if !useTLS {
		client.Transport = &http.Transport{
			DialContext:        (&net.Dialer{Timeout: s.timeout}).DialContext,
			ForceAttemptHTTP2: true,
		}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(frame)))
	if err != nil {
		return "", false
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")

	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", false
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil || len(respBody) < 6 {
		return "", false
	}

	msgLen := binary.BigEndian.Uint32(respBody[1:5])
	if int(msgLen)+5 > len(respBody) {
		return "", false
	}
	msg := respBody[5 : 5+msgLen]

	// Parse HealthCheckResponse { int32 status = 1; }
	if len(msg) > 0 && msg[0] == 0x08 { // field 1, varint
		if len(msg) > 1 {
			status, _ := readVarint(msg[1:])
			switch status {
			case 1:
				return "SERVING", true
			case 2:
				return "NOT_SERVING", true
			case 3:
				return "UNKNOWN", true
			default:
				return fmt.Sprintf("status_%d", status), true
			}
		}
	}

	return "", false
}

// reflectMethods requests the FileDescriptorProto for a service symbol
// and extracts method names from it.
// ServerReflectionRequest with file_containing_symbol: "service.Name"
// → ServerReflectionResponse with file_descriptor_response → FileDescriptorProto
func (s *GRPCScanner) reflectMethods(ctx context.Context, target string, useTLS bool, symbol string) ([]string, error) {
	// Build ServerReflectionRequest with file_containing_symbol (field 4)
	// Tag = (4 << 3) | 2 = 34
	reqBody := []byte{34, byte(len(symbol))}
	reqBody = append(reqBody, []byte(symbol)...)

	// Build gRPC frame
	frame := make([]byte, 5+len(reqBody))
	frame[0] = 0
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(reqBody)))
	copy(frame[5:], reqBody)

	scheme := "https"
	if !useTLS {
		scheme = "http"
	}
	url := fmt.Sprintf("%s://%s/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo", scheme, target)

	client := &http.Client{Timeout: s.timeout}
	if !useTLS {
		client.Transport = &http.Transport{
			DialContext:        (&net.Dialer{Timeout: s.timeout}).DialContext,
			ForceAttemptHTTP2: true,
		}
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(frame)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("TE", "trailers")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("gRPC status: %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(respBody) < 5 {
		return nil, fmt.Errorf("response too short")
	}

	msgLen := binary.BigEndian.Uint32(respBody[1:5])
	if int(msgLen)+5 > len(respBody) {
		return nil, fmt.Errorf("incomplete gRPC frame")
	}
	msg := respBody[5 : 5+msgLen]

	// Parse ServerReflectionResponse for file_descriptor_response (field 6)
	// file_descriptor_response contains repeated bytes (serialized FileDescriptorProto)
	fdProtoBytes := s.extractFileDescriptorProto(msg)
	if len(fdProtoBytes) == 0 {
		return nil, fmt.Errorf("no file descriptor in response")
	}

	// Parse FileDescriptorProto to extract service methods
	return s.parseFileDescriptorMethods(fdProtoBytes, symbol), nil
}

// extractFileDescriptorProto gets the raw FileDescriptorProto bytes
// from a ServerReflectionResponse
func (s *GRPCScanner) extractFileDescriptorProto(msg []byte) []byte {
	pos := 0
	for pos < len(msg) {
		if pos >= len(msg) {
			break
		}
		tag := msg[pos]
		pos++
		wireType := tag & 0x07
		fieldNum := tag >> 3

		if wireType == 2 { // length-delimited
			length, n := readVarint(msg[pos:])
			pos += n
			if pos+int(length) > len(msg) {
				break
			}
			value := msg[pos : pos+int(length)]
			pos += int(length)

			if fieldNum == 6 { // file_descriptor_response
				// FileDescriptorResponse { repeated bytes file_descriptor_proto = 1; }
				return s.extractFileDescriptorBytes(value)
			}
		} else if wireType == 0 {
			_, n := readVarint(msg[pos:])
			pos += n
		} else if wireType == 5 {
			pos += 4
		} else if wireType == 1 {
			pos += 8
		}
	}
	return nil
}

// extractFileDescriptorBytes gets the raw bytes from FileDescriptorResponse
func (s *GRPCScanner) extractFileDescriptorBytes(msg []byte) []byte {
	pos := 0
	for pos < len(msg) {
		tag := msg[pos]
		pos++
		wireType := tag & 0x07
		fieldNum := tag >> 3

		if wireType == 2 && fieldNum == 1 { // file_descriptor_proto bytes
			length, n := readVarint(msg[pos:])
			pos += n
			if pos+int(length) > len(msg) {
				break
			}
			return msg[pos : pos+int(length)]
		} else if wireType == 0 {
			_, n := readVarint(msg[pos:])
			pos += n
		} else if wireType == 5 {
			pos += 4
		} else if wireType == 1 {
			pos += 8
		} else if wireType == 2 {
			length, n := readVarint(msg[pos:])
			pos += n
			pos += int(length)
		}
	}
	return nil
}

// parseFileDescriptorMethods extracts method names from a FileDescriptorProto
// for a specific service.
// FileDescriptorProto { repeated DescriptorProto service = 6; }
// ServiceDescriptorProto { string name = 1; repeated MethodDescriptorProto method = 2; }
// MethodDescriptorProto { string name = 1; string input_type = 2; string output_type = 3; }
func (s *GRPCScanner) parseFileDescriptorMethods(msg []byte, serviceName string) []string {
	var methods []string
	pos := 0

	for pos < len(msg) {
		if pos >= len(msg) {
			break
		}
		tag := msg[pos]
		pos++
		wireType := tag & 0x07
		fieldNum := tag >> 3

		if wireType == 2 { // length-delimited
			length, n := readVarint(msg[pos:])
			pos += n
			if pos+int(length) > len(msg) {
				break
			}
			value := msg[pos : pos+int(length)]
			pos += int(length)

			if fieldNum == 6 { // service (ServiceDescriptorProto)
				svcMethods := s.parseServiceMethods(value, serviceName)
				methods = append(methods, svcMethods...)
			}
		} else if wireType == 0 {
			_, n := readVarint(msg[pos:])
			pos += n
		} else if wireType == 5 {
			pos += 4
		} else if wireType == 1 {
			pos += 8
		}
	}
	return methods
}

// parseServiceMethods extracts method names from a ServiceDescriptorProto
func (s *GRPCScanner) parseServiceMethods(msg []byte, serviceName string) []string {
	var methods []string
	svcName := ""
	pos := 0

	// First pass: get service name
	for pos < len(msg) {
		tag := msg[pos]
		pos++
		wireType := tag & 0x07
		fieldNum := tag >> 3

		if wireType == 2 && fieldNum == 1 { // name
			length, n := readVarint(msg[pos:])
			pos += n
			if pos+int(length) > len(msg) {
				break
			}
			svcName = string(msg[pos : pos+int(length)])
			pos += int(length)
		} else if wireType == 2 && fieldNum == 2 { // method
			length, n := readVarint(msg[pos:])
			pos += n
			if pos+int(length) > len(msg) {
				break
			}
			value := msg[pos : pos+int(length)]
			pos += int(length)
			methodName := s.parseMethodName(value)
			if methodName != "" {
				methods = append(methods, methodName)
			}
		} else if wireType == 0 {
			_, n := readVarint(msg[pos:])
			pos += n
		} else if wireType == 5 {
			pos += 4
		} else if wireType == 1 {
			pos += 8
		} else if wireType == 2 {
			length, n := readVarint(msg[pos:])
			pos += n
			pos += int(length)
		}
	}

	// If a specific service name was requested, only return methods from that service
	if serviceName != "" && svcName != "" && !strings.HasSuffix(serviceName, svcName) {
		return nil
	}
	return methods
}

// parseMethodName extracts the name from a MethodDescriptorProto
func (s *GRPCScanner) parseMethodName(msg []byte) string {
	pos := 0
	for pos < len(msg) {
		tag := msg[pos]
		pos++
		wireType := tag & 0x07
		fieldNum := tag >> 3

		if wireType == 2 && fieldNum == 1 { // name
			length, n := readVarint(msg[pos:])
			pos += n
			if pos+int(length) > len(msg) {
				break
			}
			return string(msg[pos : pos+int(length)])
		} else if wireType == 0 {
			_, n := readVarint(msg[pos:])
			pos += n
		} else if wireType == 5 {
			pos += 4
		} else if wireType == 1 {
			pos += 8
		} else if wireType == 2 {
			length, n := readVarint(msg[pos:])
			pos += n
			pos += int(length)
		}
	}
	return ""
}

// readVarint reads a protobuf varint from a byte slice
func readVarint(data []byte) (uint64, int) {
	var result uint64
	var shift uint
	for i, b := range data {
		result |= uint64(b&0x7F) << shift
		if b&0x80 == 0 {
			return result, i + 1
		}
		shift += 7
		if shift >= 64 {
			return 0, len(data)
		}
	}
	return 0, len(data)
}
