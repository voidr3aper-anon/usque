package config

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Config represents the application configuration structure, containing essential details such as keys, endpoints, and access tokens.
type Config struct {
	PrivateKey     string `json:"private_key"`      // Base64-encoded ECDSA private key
	EndpointV4     string `json:"endpoint_v4"`      // IPv4 address of the endpoint
	EndpointV6     string `json:"endpoint_v6"`      // IPv6 address of the endpoint
	EndpointV4Port string `json:"endpoint_v4_port"` // Optional port for IPv4 endpoint
	EndpointV6Port string `json:"endpoint_v6_port"` // Optional port for IPv6 endpoint
	EndpointPubKey string `json:"endpoint_pub_key"` // PEM-encoded ECDSA public key of the endpoint to verify against
	License        string `json:"license"`          // Application license key
	ID             string `json:"id"`               // Device unique identifier
	AccessToken    string `json:"access_token"`     // Authentication token for API access
	IPv4           string `json:"ipv4"`             // Assigned IPv4 address
	IPv6           string `json:"ipv6"`             // Assigned IPv6 address
}

// AppConfig holds the global application configuration.
var AppConfig Config

// ConfigLoaded indicates whether the configuration has been successfully loaded.
var ConfigLoaded bool

// LoadConfig loads the application configuration from a JSON file.
//
// Parameters:
//   - configPath: string - The path to the configuration JSON file.
//
// Returns:
//   - error: An error if the configuration file cannot be loaded or parsed.
func LoadConfig(configPath string) error {
	file, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&AppConfig); err != nil {
		return fmt.Errorf("failed to decode config file: %v", err)
	}

	ConfigLoaded = true

	return nil
}

// SaveConfig writes the current application configuration to a prettified JSON file.
//
// Parameters:
//   - configPath: string - The path to save the configuration JSON file.
//
// Returns:
//   - error: An error if the configuration file cannot be written.
func (*Config) SaveConfig(configPath string) error {
	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(AppConfig); err != nil {
		return fmt.Errorf("failed to encode config file: %v", err)
	}

	return nil
}

// GetEcPrivateKey retrieves the ECDSA private key from the stored Base64-encoded string.
//
// Returns:
//   - *ecdsa.PrivateKey: The parsed ECDSA private key.
//   - error: An error if decoding or parsing the private key fails.
func (*Config) GetEcPrivateKey() (*ecdsa.PrivateKey, error) {
	privKeyB64, err := base64.StdEncoding.DecodeString(AppConfig.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	privKey, err := x509.ParseECPrivateKey(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	return privKey, nil
}

// GetEcEndpointPublicKey retrieves the ECDSA public key from the stored PEM-encoded string.
//
// Returns:
//   - *ecdsa.PublicKey: The parsed ECDSA public key.
//   - error: An error if decoding or parsing the public key fails.
func (*Config) GetEcEndpointPublicKey() (*ecdsa.PublicKey, error) {
	endpointPubKeyB64, _ := pem.Decode([]byte(AppConfig.EndpointPubKey))
	if endpointPubKeyB64 == nil {
		return nil, fmt.Errorf("failed to decode endpoint public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(endpointPubKeyB64.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to assert public key as ECDSA")
	}

	return ecPubKey, nil
}

// ParseIPFromEndpoint attempts to extract a plain IP from a configuration endpoint string.
// It accepts the following common formats and returns a net.IP when successful:
//   - plain IP: "1.2.3.4" or "2606:..."
//   - IP with port: "1.2.3.4:443"
//   - bracketed IPv6 with port: "[2606:...]:443"
//   - bracketed IPv6 without port: "[2606:...]" which this goes through default port 443  to connect
// 
// Returns an error when no valid IP can be parsed.
func ParseIPFromEndpoint(endpoint string) (net.IP, error) {
	// Try direct parse first (covers plain IPv4 and IPv6)
	if ip := net.ParseIP(endpoint); ip != nil {
		return ip, nil
	}

	host := endpoint
	// Try SplitHostPort which handles "[ipv6]:port" and "ipv4:port"
	if strings.Contains(endpoint, ":") {
		h, _, err := net.SplitHostPort(endpoint)
		if err == nil {
			host = h
		} else if addrErr, ok := err.(*net.AddrError); ok && strings.Contains(addrErr.Err, "missing port") {
		} else {
			host = endpoint
		}
	}

	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")

	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}

	return nil, fmt.Errorf("failed to parse IP from endpoint %q: not a valid IPv4/IPv6 literal", endpoint)
}

// GetConnectPort returns the port to use for MASQUE connection.
// Priority:
// 1. CLI provided port (if cliChanged is true)
// 2. Config endpoint_v6_port or endpoint_v4_port depending on useIPv6
// 3. cliPort (fallback)
func GetConnectPort(useIPv6 bool, cliPort int, cliChanged bool) (int, error) {
	if cliChanged {
		return cliPort, nil
	}
	if useIPv6 {
		if AppConfig.EndpointV6Port != "" {
			p, err := strconv.Atoi(AppConfig.EndpointV6Port)
			if err != nil {
				return 0, fmt.Errorf("invalid endpoint_v6_port: %v", err)
			}
			return p, nil
		}
	} else {
		if AppConfig.EndpointV4Port != "" {
			p, err := strconv.Atoi(AppConfig.EndpointV4Port)
			if err != nil {
				return 0, fmt.Errorf("invalid endpoint_v4_port: %v", err)
			}
			return p, nil
		}
	}
	return cliPort, nil
}
