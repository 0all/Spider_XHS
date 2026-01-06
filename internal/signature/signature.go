package signature

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
type Signer struct{}

// NewSigner creates a signer instance.
func NewSigner() *Signer {
	return &Signer{}
}

// Sign produces xs/xt/xs-common values for the given request metadata.
func (s *Signer) Sign(api, method, a1 string, payload interface{}) (*Signature, error) {
	if a1 == "" {
		return nil, fmt.Errorf("cookie a1 is required for signing")
	}
	xs := signXs(strings.ToUpper(method), api, strings.TrimSpace(a1), "xhs-pc-web", payload)
	xt := time.Now().UnixMilli()
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
	content := buildContentString(method, uri, payload)
	dVal := md5Hex(content)
	body := buildPayload(dVal, a1, appID, content)
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
		if payload == nil {
			return uri + "null"
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

func rand32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:])
}

func randByte(min, max int) byte {
	if max <= min {
		return byte(min)
	}
	return byte(min + int(rand32()%(uint32(max-min+1))))
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

func buildPayload(dHex, a1, appID, content string) []byte {
	payload := make([]byte, 0, 200)
	payload = append(payload, versionBytes...)

	seed := rand32()
	seedBytes := intToLE(seed, 4)
	payload = append(payload, seedBytes...)
	seedByte0 := seedBytes[0]

	timestamp := time.Now().UnixMilli()
	payload = append(payload, envFingerprintA(timestamp, 41)...)

	timeOffset := randByte(10, 50)
	payload = append(payload, envFingerprintB(timestamp-int64(timeOffset))...)

	sequenceValue := randByte(15, 50)
	payload = append(payload, intToLE(uint32(sequenceValue), 4)...)

	windowPropsLength := randByte(900, 1200)
	payload = append(payload, intToLE(uint32(windowPropsLength), 4)...)

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
	for i, b := range arr {
		out[i] = (b ^ hexKeyBytes[i]) & 0xff
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
	data := map[string]interface{}{
		"s0":  5,
		"s1":  "",
		"x0":  "1",
		"x1":  "4.2.6",
		"x2":  "Windows",
		"x3":  "xhs-pc-web",
		"x4":  "4.84.1",
		"x5":  a1,
		"x6":  xt,
		"x7":  xs,
		"x8":  fff,
		"x9":  crc32Custom(strconv.FormatInt(xt, 10) + xs + fff),
		"x10": 0,
		"x11": "normal",
	}
	payload, _ := json.Marshal(data)
	return b64Encode(encodeUtf8(string(payload)))
}
