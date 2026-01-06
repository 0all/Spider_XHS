package signature

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Signature represents the cryptographic headers required by XHS.
type Signature struct {
	Xs       string `json:"xs"`
	Xt       int64  `json:"xt"`
	XsCommon string `json:"xs_common"`
}

// Signer computes xs/xt/xs-common fully in Go (no external Node.js runtime).
type Signer struct {
	randSource io.Reader
	nowFn      func() time.Time
}

// NewSigner creates a signer instance with runtime randomness.
func NewSigner() *Signer {
	return &Signer{randSource: rand.Reader, nowFn: time.Now}
}

// NewDeterministicSigner creates a signer with injected randomness/time for testing.
func NewDeterministicSigner(r io.Reader, now func() time.Time) *Signer {
	return &Signer{randSource: r, nowFn: now}
}

// Sign produces xs/xt/xs-common values for the given request metadata.
func (s *Signer) Sign(api, method, a1 string, payload interface{}) (*Signature, error) {
	if a1 == "" {
		return nil, fmt.Errorf("cookie a1 is required for signing")
	}
	now := s.nowFn
	r := s.randSource
	if now == nil {
		now = time.Now
	}
	if r == nil {
		r = rand.Reader
	}
	xs := signXsWithSources(strings.ToUpper(method), api, strings.TrimSpace(a1), "xhs-pc-web", payload, r, now)
	xt := now().UnixMilli()
	xsCommon := xsCommon(strings.TrimSpace(a1), xs, xt)
	return &Signature{
		Xs:       xs,
		Xt:       xt,
		XsCommon: xsCommon,
	}, nil
}

// ----- Implementation translated from static/xhs_xs_xsc_56.js (simplified, Go-only) -----

const (
	customAlphabet   = "ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5"
	standardAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	x3Alphabet       = "MfgqrsbcyzPQRStuvC7mn501HIJBo2DEFTKdeNOwxWXYZap89+/A4UVLhijkl63G"
	x3Prefix         = "mns0301_"
	xysPrefix        = "XYS_"
	fff              = "I38rHdgsjopgIvesdVwgIC+oIELmBZ5e3VwXLgFTIxS3bqwErFeexd0ekncAzMFYnqthIhJeSnMDKutRI3KsYorWHPtGrbV0P9WfIi/eWc6eYqtyQApPI37ekmR6QL+5Ii6sdneeSfqYHqwl2qt5B0DBIx++GDi/sVtkIxdsxuwr4qtiIhuaIE3e3LV0I3VTIC7e0utl2ADmsLveDSKsSPw5IEvsiVtJOqw8BuwfPpdeTFWOIx4TIiu6ZPwbPut5IvlaLbgs3qtxIxes1VwHIkumIkIyejgsY/WTge7eSqte/D7sDcpipedeYrDtIC6eDVw2IENsSqtlnlSuNjVtIvoekqt3cZ7sVo4gIESyIhE4NnquIxhnqz8gIkIfoqwkICZW8g3sdlOeVPw3IvAe0fged0YyIi5s3Mc52utAIiKsidvekZNeTPt4nAOeWPwEIvSzaAdeSVwXpnesDqwmI3TrIxE5Luwwaqw+rekhZANe1MNe0Pw9ICNsVLoeSbIFIkosSr7sVnFiIkgsVVtMIiudqqw+tqtWI30e3PwIIhoe3ut1IiOsjut3wutnsPwXICclI3Ir27lk2I5e1utCIES/IEJs0PtnpYIAO0JeYfD1IErPOPtKoqw3I3OexqtWQL5eiz0sVSEyIEJekd/skPtsnPwqICJeSPwiIh5eVAuLIv5eYo/e0PtSICKsVqwV4omqI3RIIkge0e0sYZ0si/7eiuwSIvTeIhqmGuwCIkrPIx0edUzbzbveTPw5IxI0yVwImZeedM0eWVwmeqt2IiM9IhhQLqwJPqtbIxZ="
	hexKey           = "71a302257793271ddd273bcee3e4b98d9d7935e1da33f5765e2ea8afb6dc77a51a499d23b67c20660025860cbf13d4540d92497f58686c574e508f46e1956344f39139bf4faf22a3eef120b79258145b2feb5193b6478669961298e79bedca646e1a693a926154a5a7a1bd1cf0dedb742f917a747a1e388b234f2277"
)

var (
	versionBytes        = []byte{119, 104, 96, 41}
	templateX           = map[string]string{"x0": "4.2.6", "x1": "xhs-pc-web", "x2": "Windows", "x3": "", "x4": ""}
	checksumFixedTail   = []byte{249, 65, 103, 103, 201, 181, 131, 99, 94, 7, 68, 250, 132, 21}
	hexKeyBytes, _      = hex.DecodeString(hexKey)
	customEncoding      = base64.NewEncoding(customAlphabet)
	customEncodingNoPad = base64.NewEncoding(customAlphabet).WithPadding('=')
	base64Std           = base64.StdEncoding
)

func signXs(method, uri, a1, appID string, payload interface{}) string {
	return signXsWithSources(method, uri, a1, appID, payload, rand.Reader, time.Now)
}

func signXsWithSources(method, uri, a1, appID string, payload interface{}, r io.Reader, now func() time.Time) string {
	content := buildContentString(method, uri, payload)
	dVal := md5Hex(content)
	body := buildPayload(dVal, a1, appID, content, now, r)
	xor := xorArray(body)
	x3Body := encodeX3(xor[:124])
	x3Full := x3Prefix + x3Body

	xTemplate := map[string]string{
		"x0": templateX["x0"],
		"x1": templateX["x1"],
		"x2": templateX["x2"],
		"x3": x3Full,
		"x4": templateX["x4"],
	}
	jsonCompact, _ := json.Marshal(xTemplate)
	encoded := b64CustomEncode(string(jsonCompact))
	return xysPrefix + encoded
}

func buildContentString(method, uri string, payload interface{}) string {
	if strings.ToUpper(method) == "POST" {
		if raw, ok := payload.(json.RawMessage); ok {
			return uri + string(raw)
		}
		if payload == nil {
			return uri + "{}"
		}
		b, _ := json.Marshal(payload)
		return uri + string(b)
	}
	// GET style
	m, ok := payload.(map[string]interface{})
	if !ok || len(m) == 0 {
		return uri
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		v := m[k]
		valStr := ""
		switch t := v.(type) {
		case []interface{}:
			strs := make([]string, 0, len(t))
			for _, vv := range t {
				strs = append(strs, fmt.Sprint(vv))
			}
			valStr = strings.Join(strs, ",")
		case []string:
			valStr = strings.Join(t, ",")
		case nil:
			valStr = ""
		default:
			valStr = fmt.Sprint(t)
		}
		valStr = strings.ReplaceAll(valStr, "=", "%3D")
		parts = append(parts, fmt.Sprintf("%s=%s", k, valStr))
	}
	return uri + "?" + strings.Join(parts, "&")
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func rand32(r io.Reader) uint32 {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		// fallback: deterministic but still returns a value
		return 0
	}
	return binary.LittleEndian.Uint32(b[:])
}

func randRange(r io.Reader, min, max int) uint32 {
	if max <= min {
		return uint32(min)
	}
	return uint32(min) + rand32(r)%uint32(max-min+1)
}

func intToLE(val uint32, length int) []byte {
	out := make([]byte, length)
	for i := 0; i < length; i++ {
		out[i] = byte(val & 0xff)
		val >>= 8
	}
	return out
}

func structPackLittleEndianQ(ts int64) []byte {
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = byte(ts & 0xff)
		ts >>= 8
	}
	return out
}

func envFingerprintA(ts int64, xorKey byte) []byte {
	data := structPackLittleEndianQ(ts)
	sum1 := int(data[1]) + int(data[2]) + int(data[3]) + int(data[4])
	sum2 := int(data[5]) + int(data[6]) + int(data[7])
	mark := byte((sum1&0xff + sum2) & 0xff)
	data[0] = mark
	for i := range data {
		data[i] ^= xorKey
	}
	return data
}

func envFingerprintB(ts int64) []byte {
	return structPackLittleEndianQ(ts)
}

func buildPayload(dHex, a1, appID, content string, now func() time.Time, r io.Reader) []byte {
	payload := make([]byte, 0, 200)
	payload = append(payload, versionBytes...)

	seed := rand32(r)
	seedBytes := intToLE(seed, 4)
	payload = append(payload, seedBytes...)
	seedByte0 := seedBytes[0]

	timestamp := now().UnixMilli()
	payload = append(payload, envFingerprintA(timestamp, 41)...)

	timeOffset := randRange(r, 10, 50)
	payload = append(payload, envFingerprintB(timestamp-int64(timeOffset))...)

	sequenceValue := randRange(r, 15, 50)
	payload = append(payload, intToLE(sequenceValue, 4)...)

	windowPropsLength := randRange(r, 900, 1200)
	payload = append(payload, intToLE(windowPropsLength, 4)...)

	uriLength := len([]byte(content))
	payload = append(payload, intToLE(uint32(uriLength), 4)...)

	md5Bytes, _ := hex.DecodeString(dHex)
	for i := 0; i < 8; i++ {
		payload = append(payload, md5Bytes[i]^seedByte0)
	}

	payload = append(payload, 52)

	paddedA1 := make([]byte, 52)
	copy(paddedA1, []byte(a1))
	payload = append(payload, paddedA1...)

	payload = append(payload, 10)

	paddedSource := make([]byte, 10)
	copy(paddedSource, []byte(appID))
	payload = append(payload, paddedSource...)

	payload = append(payload, 1)
	payload = append(payload, 1) // CHECKSUM_VERSION
	payload = append(payload, seedByte0^115)
	payload = append(payload, checksumFixedTail...)

	return payload
}

func xorArray(arr []byte) []byte {
	out := make([]byte, len(arr))
	keyLen := len(hexKeyBytes)
	for i, b := range arr {
		out[i] = (b ^ hexKeyBytes[i%keyLen]) & 0xff
	}
	return out
}

func encodeX3(bytes []byte) string {
	std := base64Std.EncodeToString(bytes)
	var builder strings.Builder
	for _, ch := range std {
		idx := strings.IndexRune(standardAlphabet, ch)
		if idx >= 0 {
			builder.WriteByte(x3Alphabet[idx])
		} else {
			builder.WriteRune(ch)
		}
	}
	return builder.String()
}

func b64CustomEncode(s string) string {
	var builder strings.Builder
	std := base64Std.EncodeToString([]byte(s))
	for _, ch := range std {
		idx := strings.IndexRune(standardAlphabet, ch)
		if idx >= 0 {
			builder.WriteByte(customAlphabet[idx])
		} else {
			builder.WriteRune(ch)
		}
	}
	return builder.String()
}

func b64Encode(data []byte) string {
	return customEncodingNoPad.EncodeToString(data)
}

func encodeUtf8(s string) []byte {
	// JS code uses encodeURIComponent then parses back to bytes; equivalent to UTF-8 bytes.
	return []byte(s)
}

func crc32Custom(input string) uint32 {
	const poly uint32 = 0xEDB88320
	table := [256]uint32{}
	for i := 0; i < 256; i++ {
		crc := uint32(i)
		for j := 0; j < 8; j++ {
			if crc&1 == 1 {
				crc = (crc >> 1) ^ poly
			} else {
				crc >>= 1
			}
		}
		table[i] = crc
	}
	crc := uint32(0xFFFFFFFF)
	for _, ch := range []byte(input) {
		crc = table[(crc^uint32(ch))&0xFF] ^ (crc >> 8)
	}
	return ^crc ^ poly
}

func xsCommon(a1, xs string, xt int64) string {
	payloadStruct := struct {
		S0  int    `json:"s0"`
		S1  string `json:"s1"`
		X0  string `json:"x0"`
		X1  string `json:"x1"`
		X2  string `json:"x2"`
		X3  string `json:"x3"`
		X4  string `json:"x4"`
		X5  string `json:"x5"`
		X6  int64  `json:"x6"`
		X7  string `json:"x7"`
		X8  string `json:"x8"`
		X9  int32  `json:"x9"`
		X10 int    `json:"x10"`
		X11 string `json:"x11"`
	}{
		S0:  5,
		S1:  "",
		X0:  "1",
		X1:  "4.2.6",
		X2:  "Windows",
		X3:  "xhs-pc-web",
		X4:  "4.84.1",
		X5:  a1,
		X6:  xt,
		X7:  xs,
		X8:  fff,
		X9:  int32(crc32Custom(strconv.FormatInt(xt, 10) + xs + fff)),
		X10: 0,
		X11: "normal",
	}
	payload, _ := json.Marshal(payloadStruct)
	return b64Encode(encodeUtf8(string(payload)))
}
