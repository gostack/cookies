package cookies

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/doximity/cookies/goRailsYourself/crypto"
)

// CookieEncryptor implements cookie encryption and signing to allow securely storing sensitive
// information on the user-agent.
type CookieEncryptor struct {
	messageEncryptor crypto.MessageEncryptor
}

// NewCookieEncryptor creates a new instance of CookieEncryptor. Creating this instance is expensive
// since it has to derives the keys.
func NewCookieEncryptor(secret string, iterations int) *CookieEncryptor {
	var (
		kg      = crypto.KeyGenerator{Secret: secret, Iterations: iterations}
		key     = kg.CacheGenerate([]byte("encrypted cookie"), 32)
		signKey = kg.CacheGenerate([]byte("signed encrypted cookie"), 64)
	)

	ce := &CookieEncryptor{
		messageEncryptor: crypto.MessageEncryptor{Key: key, SignKey: signKey, Serializer: crypto.NullMsgSerializer{}},
	}

	return ce
}

// Encrypt takes an http.Cookie instance and encrypts and sign it's value, replacing it.
func (ce *CookieEncryptor) Encrypt(cookie *http.Cookie) error {
	encValue, err := ce.messageEncryptor.EncryptAndSign(cookie.Value)
	if err != nil {
		return err
	}

	cookie.Value = encValue
	return nil
}

// Decrypt takes an encrypted http.Cookie instance and decrypts it.
func (ce *CookieEncryptor) Decrypt(cookie *http.Cookie) error {
	var value string

	if cookie.Value == "" {
		return http.ErrNoCookie
	}

	err := ce.messageEncryptor.DecryptAndVerify(cookie.Value, &value)
	if err != nil {
		return err
	}

	cookie.Value = value
	return nil
}

// CookieEncoder encodes/decodes a specific data structure into a cookie's content.
type CookieEncoder interface {
	Encode(v interface{}, c *http.Cookie) error
	Decode(v interface{}, c *http.Cookie) error
}

// JSONCookieEncoder encodes/decodes cookies using encoding/json
type JSONCookieEncoder struct{}

func (e JSONCookieEncoder) Encode(v interface{}, c *http.Cookie) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	c.Value = string(b)
	return nil
}

func (e JSONCookieEncoder) Decode(v interface{}, c *http.Cookie) error {
	if err := json.Unmarshal([]byte(c.Value), v); err != nil {
		return err
	}

	return nil
}

type SecureCookieManager struct {
	Encryptor *CookieEncryptor
	Encoder   CookieEncoder
}

type CookieOptions struct {
	Domain   string
	Path     string
	HTTPOnly bool
	Secure   bool
	MaxAge   time.Duration
	Expires  time.Time
	SameSite http.SameSite
}

// Set a cookie with the data set to the encrypted version of the serialization of v.
// Returns the http.Cookie generated.
func (cm *SecureCookieManager) Set(w http.ResponseWriter, name string, opts *CookieOptions, v interface{}) (*http.Cookie, error) {
	var err error

	if opts == nil {
		opts = &CookieOptions{}
	}

	cookie := http.Cookie{
		Name:     name,
		Domain:   opts.Domain,
		Path:     opts.Path,
		HttpOnly: opts.HTTPOnly,
		Secure:   opts.Secure,
		MaxAge:   int(opts.MaxAge.Seconds()),
		Expires:  opts.Expires,
		SameSite: opts.SameSite,
	}

	if err := cm.Encoder.Encode(v, &cookie); err != nil {
		return &cookie, err
	}

	if err = cm.Encryptor.Encrypt(&cookie); err != nil {
		return &cookie, err
	}

	http.SetCookie(w, &cookie)
	return &cookie, nil
}

// Get gets the Cookie, decrypted it and deserialized it into v.
// Returns the decrypted cookie.
func (cm *SecureCookieManager) Get(req *http.Request, name string, v interface{}) (*http.Cookie, error) {
	cookie, err := req.Cookie(name)
	if err != nil {
		return nil, err
	}

	if err := cm.Encryptor.Decrypt(cookie); err != nil {
		return cookie, err
	}

	if err := cm.Encoder.Decode(v, cookie); err != nil {
		return cookie, err
	}

	return cookie, nil
}

// Deletes the Cookie, setting value to empty and expiring in the past.
func (cm *SecureCookieManager) Delete(w http.ResponseWriter, name string, opts *CookieOptions) (*http.Cookie, error) {
	if opts == nil {
		opts = &CookieOptions{}
	}

	cookie := http.Cookie{
		Name:     name,
		HttpOnly: opts.HTTPOnly,
		Domain:   opts.Domain,
		Secure:   opts.Secure,
		Path:     opts.Path,
		MaxAge:   -1,
	}

	http.SetCookie(w, &cookie)
	return &cookie, nil
}
