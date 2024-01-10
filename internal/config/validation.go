// Package config implements all configuration aspects of lego-auto
package config

import (
	"github.com/bjw-s/lego-auto/pkg/helpers"
	"github.com/gookit/validate"
	"golang.org/x/exp/slices"
)

// ValidateFolder validates that the path is a valid folder
func (c Config) ValidateFolder(val string) bool {
	return helpers.FolderExists(val)
}

// Validate returns if the given configuration is valid and any validation errors
func (c *Config) Validate() validate.Errors {
	v := validate.Struct(c)
	v.StopOnError = false
	return v.ValidateE()
}

// ValidateDirectory validates that the Directory is valid
func (c Config) ValidateDirectory(val string) bool {
	validDirectories := []string{"production", "staging"}
	return slices.Contains(validDirectories, val)
}

// ValidateCA validates that the CA is valid
func (c Config) ValidateCA(val string) bool {
	validCa := []string{"letsencrypt", "google"}
	return slices.Contains(validCa, val)
}

// ValidateKeyType validates that the KeyType is valid
func (c Config) ValidateKeyType(val string) bool {
	validKeyType := []string{
		"P256", // EC256
		"P384", // EC384
		"2048", // RSA2048
		"3072", // RSA3072
		"4096", // RSA4096
		"8192", // RSA8192
	}
	return slices.Contains(validKeyType, val)
}

func (c Config) Messages() map[string]string {
	return validate.MS{
		"ValidateFolder":    "{field} must point to a valid folder.",
		"ValidateDirectory": "Directory must be one of: production, staging",
		"ValidateCA":        "CA must be one of: letsencrypt, google",
		"ValidateKeyType":   "Key Type must be one of: P256, P384, 2048, 3072, 4096, 8192",
	}
}
