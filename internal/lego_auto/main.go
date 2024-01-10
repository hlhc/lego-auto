// Package lego_auto implements all lego-auto functionality
package lego_auto

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	publicca "cloud.google.com/go/security/publicca/apiv1beta1"
	"cloud.google.com/go/security/publicca/apiv1beta1/publiccapb"
	"github.com/bjw-s/lego-auto/internal/ca"
	"github.com/bjw-s/lego-auto/internal/config"
	"github.com/bjw-s/lego-auto/pkg/helpers"
	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"google.golang.org/api/option"
)

// AppConfig contains the appConfig instance used by lego-auto
var AppConfig *config.Config

// Run executes the main lego-auto logic
func Run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	account, err := getOrCreateAccount()
	if err != nil {
		fmt.Printf("Failed to get account: %s\n", err)
		os.Exit(1)
	}

	log.Infof("acme: Setting challenger for provider %s", AppConfig.DNSProvider)
	if err := setupChallenge(account); err != nil {
		log.Fatalf("Failed to set challenge: %s\n", err)
	}

	for {
		log.Infof("issuing or renewing certificates as needed")
		if list, err := issueOrRenewCerts(ctx, account); err != nil {
			log.Warnf("Failed to issue cert: %s\n", err)
		} else if err := exportCertsToDataDir(ctx, list); err != nil {
			log.Warnf("Failed to move certificate to data folder: %s\n", err)
		}
		log.Infof("Done, next check after 1 hour")
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(time.Hour):
		}
	}
}

type legoAccount struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *legoAccount) GetEmail() string {
	return u.Email
}
func (u legoAccount) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *legoAccount) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

func (la *legoAccount) Save(file string) error {
	return helpers.AtomicJSON(file, la)
}

func getOrCreateAccount() (*lego.Client, error) {
	accountFile := filepath.Join(AppConfig.CacheDir, AppConfig.Email+".json")
	account, err := loadAccount(accountFile)
	if err == nil {
		log.Infof("acme: Using saved account")
		return lego.NewClient(lego.NewConfig(account))
	}

	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	log.Infof("acme: Generating new account")

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	user := &legoAccount{
		Email: AppConfig.Email,
		Key:   privateKey,
	}

	config := lego.NewConfig(user)

	// Set ACME Directory URL
	if AppConfig.CA == "google" {
		if AppConfig.Directory == "staging" {
			config.CADirURL = ca.GoogleDirectoryStaging
		} else {
			config.CADirURL = ca.GoogleDirectoryProduction
		}
	} else if AppConfig.CA == "letsencrypt" {
		if AppConfig.Directory == "staging" {
			config.CADirURL = lego.LEDirectoryStaging
		} else {
			config.CADirURL = lego.LEDirectoryProduction
		}
	}

	// Set Key Type
	config.Certificate.KeyType = certcrypto.KeyType(AppConfig.KeyType)

	// Create a new client instance
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	//
	var reg *registration.Resource
	if AppConfig.CA == "google" {
		eabOption, err := getGoogleAcmeAuth()
		if err != nil {
			return nil, err
		}
		reg, err = client.Registration.RegisterWithExternalAccountBinding(*eabOption)
		if err != nil {
			return nil, err
		}
	} else if AppConfig.CA == "letsencrypt" {
		reg, err = client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	}

	if err != nil {
		fmt.Printf("ERROR: %s\n", err)
		return nil, err
	}

	user.Registration = reg

	return client, user.Save(accountFile)
}

func loadAccount(file string) (*legoAccount, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var acc legoAccount

	return &acc, json.NewDecoder(f).Decode(&acc)
}

func getGoogleAcmeAuth() (*registration.RegisterEABOptions, error) {
	str, err := base64.StdEncoding.DecodeString(AppConfig.AcmeCredentials)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	cred := []byte(str)
	c, err := publicca.NewPublicCertificateAuthorityClient(ctx, option.WithCredentialsJSON(cred))
	if err != nil {
		return nil, err
	}
	defer c.Close()

	req := &publiccapb.CreateExternalAccountKeyRequest{
		Parent:             fmt.Sprintf("projects/%s/locations/global", AppConfig.GCloudProject),
		ExternalAccountKey: &publiccapb.ExternalAccountKey{},
	}
	resp, err := c.CreateExternalAccountKey(ctx, req)
	if err != nil {
		return nil, err
	}

	eabOption := &registration.RegisterEABOptions{
		TermsOfServiceAgreed: true,
		HmacEncoded:          string(resp.B64MacKey),
		Kid:                  resp.KeyId,
	}

	return eabOption, nil
}

func setupChallenge(lgc *lego.Client) error {
	provider, err := dns.NewDNSChallengeProviderByName(AppConfig.DNSProvider)
	if err != nil {
		return err
	}

	var opts = []dns01.ChallengeOption{
		dns01.AddDNSTimeout(AppConfig.Timeout),
	}
	if len(AppConfig.DNS) > 0 {
		opts = append(opts, dns01.AddRecursiveNameservers(AppConfig.DNS))
	}
	return lgc.Challenge.SetDNS01Provider(provider, opts...)
}

func issueOrRenewCerts(ctx context.Context, lgc *lego.Client) ([]*certificate.Resource, error) {
	var certs []*certificate.Resource

	primaryDomain := AppConfig.Domains[0]

	cert, err := loadCert(AppConfig.CacheDir, primaryDomain)
	if errors.Is(err, os.ErrNotExist) {
		log.Infof("issuing new certificate for %s", primaryDomain)
		// issue certificate
		cert, err = issueCert(AppConfig.Domains, lgc)
		if err != nil {
			return nil, fmt.Errorf("issue new certificate for %s: %w", primaryDomain, err)
		}
	} else if err != nil {
		// something happened during load
		return certs, err
	} else if crt, err := helpers.ParseCert(cert); err != nil {
		// parsing failed
		return certs, err
	} else if time.Now().After(crt.NotAfter) {
		log.Infof("Issuing new certificate because the old one expired for %s", primaryDomain)
		// certificate has expired, issue new certificate
		cert, err = issueCert(AppConfig.Domains, lgc)
		if err != nil {
			return nil, fmt.Errorf("issue new certificate for %s: %w", primaryDomain, err)
		}
	} else if time.Until(crt.NotAfter) <= AppConfig.RenewBefore {
		// renew if the certificate will expire soon
		cert, err = renewCert(cert, lgc)
		if err != nil {
			return nil, fmt.Errorf("issue new certificate for %s: %w", primaryDomain, err)
		}
	}
	certs = append(certs, cert)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return certs, nil
}

func issueCert(domains []string, lgc *lego.Client) (*certificate.Resource, error) {
	request, err := lgc.Certificate.Obtain(certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	})
	if err != nil {
		return nil, fmt.Errorf("create certificate request for: %w", err)
	}
	return request, saveCert(AppConfig.CacheDir, request)
}

func renewCert(res *certificate.Resource, lgc *lego.Client) (*certificate.Resource, error) {
	ng, err := lgc.Certificate.Renew(*res, true, false, "")
	if err != nil {
		return nil, err
	}
	return ng, saveCert(AppConfig.CacheDir, ng)
}

func saveCert(dir string, resource *certificate.Resource) error {
	return helpers.AtomicJSON(filepath.Join(dir, resource.Domain+".json"), serializedCertificate{
		Domain:            resource.Domain,
		CertURL:           resource.CertURL,
		CertStableURL:     resource.CertStableURL,
		PrivateKey:        resource.PrivateKey,
		Certificate:       resource.Certificate,
		IssuerCertificate: resource.IssuerCertificate,
		CSR:               resource.CSR,
	})
}

func loadCert(dir, domain string) (*certificate.Resource, error) {
	f, err := os.Open(filepath.Join(dir, domain+".json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var resource serializedCertificate
	err = json.NewDecoder(f).Decode(&resource)
	if err != nil {
		return nil, err
	}

	return &certificate.Resource{
		Domain:            resource.Domain,
		CertURL:           resource.CertURL,
		CertStableURL:     resource.CertStableURL,
		PrivateKey:        resource.PrivateKey,
		Certificate:       resource.Certificate,
		IssuerCertificate: resource.IssuerCertificate,
		CSR:               resource.CSR,
	}, nil
}

type serializedCertificate struct {
	Domain            string `json:"domain"`
	CertURL           string `json:"certUrl"`
	CertStableURL     string `json:"certStableUrl"`
	PrivateKey        []byte `json:"privateKey"`
	Certificate       []byte `json:"certificate"`
	IssuerCertificate []byte `json:"issuer_certificate"`
	CSR               []byte `json:"csr"`
}

func exportCertsToDataDir(ctx context.Context, certs []*certificate.Resource) error {
	for _, res := range certs {
		certFile := fmt.Sprintf("%s/fullchain.pem", AppConfig.DataDir)
		immediateFile := fmt.Sprintf("%s/immediate.pem", AppConfig.DataDir)
		keyFile := fmt.Sprintf("%s/privkey.pem", AppConfig.DataDir)
		combinedFile := fmt.Sprintf("%s/combined.pem", AppConfig.DataDir)

		// Export Certificate
		log.Infof("Exporting certificate of %s to %s", res.Domain, certFile)
		err := os.WriteFile(certFile, res.Certificate, 0644)
		if err != nil {
			return fmt.Errorf("exporting certificate failed %s: %w", res.Domain, err)
		}

		// Export Certificate with Immediate CA
		log.Infof("Exporting certificate with only immediate CA of %s to %s", res.Domain, immediateFile)
		imm, err := parseImmediateCAOnly(res.Certificate)
		if err != nil {
			return fmt.Errorf("parse certificate failed %s: %w", res.Domain, err)
		}
		err = os.WriteFile(immediateFile, imm, 0644)
		if err != nil {
			return fmt.Errorf("exporting certificate with only immediate CA failed %s: %w", res.Domain, err)
		}

		// Export Private Key
		log.Infof("Exporting private key of %s to %s", res.Domain, keyFile)
		err = os.WriteFile(keyFile, res.PrivateKey, 0600)
		if err != nil {
			return fmt.Errorf("exporting private key failed failed %s: %w", res.Domain, err)
		}

		// Export Combined Key + Cert
		log.Infof("Exporting combined key+cert of %s to %s", res.Domain, combinedFile)
		var combinedOutput []byte
		combinedOutput = append(combinedOutput, res.PrivateKey...)
		combinedOutput = append(combinedOutput, []byte("\n")...)
		combinedOutput = append(combinedOutput, res.Certificate...)
		err = os.WriteFile(combinedFile, combinedOutput, 0600)
		if err != nil {
			return fmt.Errorf("exporting combined file failed failed %s: %w", res.Domain, err)
		}
	}

	return nil
}

func parseImmediateCAOnly(bundle []byte) ([]byte, error) {
	var certificates []*x509.Certificate
	var certDERBlock *pem.Block

	for {
		certDERBlock, bundle = pem.Decode(bundle)
		if certDERBlock == nil {
			break
		}

		if certDERBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(certDERBlock.Bytes)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, cert)
		}
	}

	if len(certificates) == 0 {
		return nil, errors.New("no certificates were found while parsing the bundle")
	}

	// lego always returns the issued cert first, if the CA is first there is a problem
	if certificates[0].IsCA {
		err := fmt.Errorf("first certificate is a CA certificate")
		return nil, err
	}

	immediate := make([]byte, 0)
	for _, crt := range certificates {
		immediate = append(immediate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw})...)

		if crt.IsCA {
			break // Only include one CA
		}
	}

	return immediate, nil
}
