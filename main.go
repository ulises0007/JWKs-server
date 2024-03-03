package main

import (
  "crypto/rand"
  "crypto/rsa"
  "crypto/x509"
  "encoding/base64"
  "encoding/json"
  "encoding/pem"
  "fmt"
  "log"
  "net/http"
  "time"

  "github.com/dgrijalva/jwt-go"
)

var (
  keys          = make(map[string]*rsa.PrivateKey)
  keysExpiration = make(map[string]time.Time)
)

func main() {
  http.HandleFunc("/jwks", jwksH)
  http.HandleFunc("/auth", authHandler)
  log.Fatal(http.ListenAndServe(":8080", nil))
}

func jwksH(w http.ResponseWriter, r *http.Request) {
  keysToServe := make(map[string]interface{})
  for kid, key := range keys {
    if !keysExpiration[kid].Before(time.Now()) {
      keysToServe[kid] = map[string]interface{}{
        "kty": "RSA",
        "alg": "RS256",
        "kid": kid,
        "use": "sig",
        "n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
        "e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
      }
    }
  }

  jwks := map[string]interface{}{
    "keys": keysToServe,
  }

  w.Header().Set("Content-Type", "application/json")
  json.NewEncoder(w).Encode(jwks)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
  keyID := r.URL.Query().Get("kid")
  var key *rsa.PrivateKey
  if keyID != "" {
    key = keys[keyID]
  }

  if key == nil || keysExpiration[keyID].Before(time.Now()) {
    // If key is nil or has expired, return an expired JWT
    key = keys["expired"]
  }

  token := jwt.New(jwt.GetSigningMethod("RS256"))
  token.Claims = jwt.MapClaims{
    "exp": time.Now().Add(1 * time.Hour).Unix(),
    "iat": time.Now().Unix(),
  }

  signedToken, err := token.SignedString(key)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  w.Header().Set("Content-Type", "text/plain")
  w.Write([]byte(signedToken))
}

func init() {
  // Generate RSA key pairs
  key, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    log.Fatalf("Failed to generate RSA: %v", err)
  }
  keys["default"] = key
  keysExpiration["default"] = time.Now().Add(24 * time.Hour)

  // Generate an expired RSA key pair
  expiredKey, err := rsa.GenerateKey(rand.Reader, 2048)
  if err != nil {
    log.Fatalf("Failed to generate RSA: %v", err)
  }
  keys["expired"] = expiredKey
  keysExpiration["expired"] = time.Now().Add(-24 * time.Hour)
}
