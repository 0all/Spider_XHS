package signature

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
)

// Signature represents the cryptographic headers required by XHS.
type Signature struct {
	Xs       string `json:"xs"`
	Xt       int64  `json:"xt"`
	XsCommon string `json:"xs_common"`
}

// Signer calls the Node.js helper to generate signing headers.
type Signer struct {
	scriptPath string
}

// NewSigner creates a signer backed by the provided Node.js helper script.
func NewSigner(scriptPath string) *Signer {
	return &Signer{scriptPath: scriptPath}
}

// Sign produces xs/xt/xs-common values for the given request metadata.
func (s *Signer) Sign(ctx context.Context, api, method, a1 string, payload interface{}) (*Signature, error) {
	if s == nil || s.scriptPath == "" {
		return nil, fmt.Errorf("signature script path is not configured")
	}
	if a1 == "" {
		return nil, fmt.Errorf("cookie a1 is required for signing")
	}

	encodedPayload := ""
	if payload != nil {
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("encode payload: %w", err)
		}
		encodedPayload = base64.StdEncoding.EncodeToString(body)
	}

	cmd := exec.CommandContext(ctx, "node", s.scriptPath, api, method, a1, encodedPayload)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("node signing failed: %w; output: %s", err, string(output))
	}

	var sig Signature
	if err := json.Unmarshal(output, &sig); err != nil {
		return nil, fmt.Errorf("decode signature: %w; output: %s", err, string(output))
	}

	if sig.Xs == "" || sig.XsCommon == "" || sig.Xt == 0 {
		return nil, fmt.Errorf("invalid signature payload returned from node helper")
	}
	return &sig, nil
}
