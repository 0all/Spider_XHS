package signature

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type jsSignature struct {
	Xs       string `json:"xs"`
	Xt       int64  `json:"xt"`
	XsCommon string `json:"xs_common"`
}

func TestSignerMatchesJS(t *testing.T) {
	randBytes := bytes.Repeat([]byte{0x01, 0x02, 0x03, 0x04}, 16)
	fixedNow := time.Unix(1700000000, 0) // deterministic timestamp

	payloadJSON := []byte(`{"keyword":"新年","page":1,"page_size":20}`)
	payloadRaw := json.RawMessage(payloadJSON)

	goSigner := NewDeterministicSigner(bytes.NewReader(randBytes), func() time.Time { return fixedNow })
	goSig, err := goSigner.Sign("/api/sns/web/v1/search/notes", "POST", "a1-test", payloadRaw)
	if err != nil {
		t.Fatalf("go signer failed: %v", err)
	}

	payloadB64 := base64.StdEncoding.EncodeToString(payloadJSON)

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	scriptPath := filepath.Join(repoRoot, "scripts", "js_sign_deterministic.js")
	cmd := exec.Command("node", scriptPath,
		hex.EncodeToString(randBytes),
		fmt.Sprintf("%d", fixedNow.UnixMilli()),
		"POST",
		"/api/sns/web/v1/search/notes",
		"a1-test",
		payloadB64,
	)
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("js signer failed: %v\nstdout/stderr: %s", err, string(output))
	}

	var jsSig jsSignature
	if err := json.Unmarshal(output, &jsSig); err != nil {
		t.Fatalf("decode js signature: %v", err)
	}

	if goSig.Xs != jsSig.Xs {
		goDecoded, _ := decodeXs(goSig.Xs)
		jsDecoded, _ := decodeXs(jsSig.Xs)
		var goMap, jsMap map[string]string
		_ = json.Unmarshal([]byte(goDecoded), &goMap)
		_ = json.Unmarshal([]byte(jsDecoded), &jsMap)
		goX3, _ := decodeX3(goMap["x3"])
		jsX3, _ := decodeX3(jsMap["x3"])
		diffIdx, goByte, jsByte := firstDiff(goX3, jsX3)
		goPayload := unxor(goX3)
		jsPayload := unxor(jsX3)
		goWinLen := binary.LittleEndian.Uint32(goPayload[28:32])
		jsWinLen := binary.LittleEndian.Uint32(jsPayload[28:32])
		t.Fatalf("xs mismatch:\ngo=%s\njs=%s\n\ngo_decoded=%s\njs_decoded=%s\nx3_diff_index=%d go_byte=%02x js_byte=%02x windowLen_go=%d windowLen_js=%d", goSig.Xs, jsSig.Xs, goDecoded, jsDecoded, diffIdx, goByte, jsByte, goWinLen, jsWinLen)
	}
	if goSig.XsCommon != jsSig.XsCommon {
		goJSON, _ := decodeXsCommon(goSig.XsCommon)
		jsJSON, _ := decodeXsCommon(jsSig.XsCommon)
		t.Fatalf("xs_common mismatch:\ngo=%s\njs=%s\n\ngo_decoded=%s\njs_decoded=%s", goSig.XsCommon, jsSig.XsCommon, goJSON, jsJSON)
	}
	if goSig.Xt != jsSig.Xt {
		t.Fatalf("xt mismatch:\ngo=%d\njs=%d", goSig.Xt, jsSig.Xt)
	}
}

func decodeXs(xs string) (string, error) {
	if !strings.HasPrefix(xs, "XYS_") {
		return "", fmt.Errorf("invalid prefix")
	}
	body := xs[len("XYS_"):]
	var builder strings.Builder
	for _, ch := range body {
		idx := strings.IndexRune(customAlphabet, ch)
		if idx >= 0 {
			builder.WriteByte(standardAlphabet[idx])
		} else {
			builder.WriteRune(ch)
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(builder.String())
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func decodeX3(x3 string) ([]byte, error) {
	if !strings.HasPrefix(x3, x3Prefix) {
		return nil, fmt.Errorf("invalid x3 prefix")
	}
	body := x3[len(x3Prefix):]
	var builder strings.Builder
	for _, ch := range body {
		idx := strings.IndexRune(x3Alphabet, ch)
		if idx >= 0 {
			builder.WriteByte(standardAlphabet[idx])
		} else {
			builder.WriteRune(ch)
		}
	}
	return base64.StdEncoding.DecodeString(builder.String())
}

func firstDiff(a, b []byte) (int, byte, byte) {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for i := 0; i < limit; i++ {
		if a[i] != b[i] {
			return i, a[i], b[i]
		}
	}
	if len(a) != len(b) {
		return limit, 0, 0
	}
	return -1, 0, 0
}

func unxor(in []byte) []byte {
	out := make([]byte, len(in))
	keyLen := len(hexKeyBytes)
	for i, b := range in {
		out[i] = b ^ hexKeyBytes[i%keyLen]
	}
	return out
}

func decodeXsCommon(xsCommon string) (string, error) {
	var builder strings.Builder
	for _, ch := range xsCommon {
		idx := strings.IndexRune(customAlphabet, ch)
		if idx >= 0 {
			builder.WriteByte(standardAlphabet[idx])
		} else {
			builder.WriteRune(ch)
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(builder.String())
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
