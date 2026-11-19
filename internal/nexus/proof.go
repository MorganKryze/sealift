package nexus

import (
	"crypto/tls"
	"net/http"
)

// proofClient exists only to check that gosec fails the lint.
var proofClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
