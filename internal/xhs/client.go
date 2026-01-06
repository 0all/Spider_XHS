package xhs

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"spider_xhs/internal/signature"
)

const baseURL = "https://edith.xiaohongshu.com"

// Client wraps the network operations required to talk to XiaoHongShu.
type Client struct {
	cookies      map[string]string
	cookieHeader string
	signer       *signature.Signer
	httpClient   *http.Client
}

// NewClient builds a Client using the provided cookie string and signer.
func NewClient(cookiesStr string, signer *signature.Signer) (*Client, error) {
	cookieMap := parseCookies(cookiesStr)
	if _, ok := cookieMap["a1"]; !ok {
		return nil, fmt.Errorf("cookie string must contain a1 key for signing")
	}
	return &Client{
		cookies:      cookieMap,
		cookieHeader: formatCookieHeader(cookieMap),
		signer:       signer,
		httpClient: &http.Client{
			Timeout: 45 * time.Second,
		},
	}, nil
}

// SearchNotes fetches note search results and returns their identifiers plus xsec tokens.
func (c *Client) SearchNotes(ctx context.Context, keyword string, limit int) ([]SearchNote, error) {
	page := 1
	collected := make([]SearchNote, 0, limit)
	for len(collected) < limit {
		payload := buildSearchPayload(keyword, page)
		respBytes, err := c.requestJSON(ctx, http.MethodPost, "/api/sns/web/v1/search/notes", payload)
		if err != nil {
			return nil, fmt.Errorf("search notes page %d: %w", page, err)
		}
		parsed, hasMore, err := parseSearchNotesResponse(respBytes)
		if err != nil {
			return nil, fmt.Errorf("parse search notes page %d: %w", page, err)
		}
		collected = append(collected, parsed...)
		if !hasMore || len(parsed) == 0 {
			break
		}
		page++
	}
	if len(collected) > limit {
		collected = collected[:limit]
	}
	return collected, nil
}

// SearchUserByRedID finds a user_id by their red-id.
func (c *Client) SearchUserByRedID(ctx context.Context, redID string) (string, error) {
	page := 1
	for page < 6 {
		payload := buildUserSearchPayload(redID, page)
		respBytes, err := c.requestJSON(ctx, http.MethodPost, "/api/sns/web/v1/search/usersearch", payload)
		if err != nil {
			return "", fmt.Errorf("search user page %d: %w", page, err)
		}
		userID, hasMore, err := extractUserIDFromSearch(respBytes, redID)
		if err != nil {
			return "", fmt.Errorf("parse user search: %w", err)
		}
		if userID != "" {
			return userID, nil
		}
		if !hasMore {
			break
		}
		page++
	}
	return "", fmt.Errorf("user with red_id %s not found", redID)
}

// FetchUserNotes enumerates a user's notes and returns IDs plus tokens.
func (c *Client) FetchUserNotes(ctx context.Context, userID string, limit int) ([]SearchNote, error) {
	cursor := ""
	collected := make([]SearchNote, 0, limit)
	for len(collected) < limit {
		api := fmt.Sprintf("/api/sns/web/v1/user_posted?num=30&cursor=%s&user_id=%s&image_formats=jpg,webp,avif&xsec_token=&xsec_source=pc_search", url.QueryEscape(cursor), url.QueryEscape(userID))
		respBytes, err := c.requestJSON(ctx, http.MethodGet, api, nil)
		if err != nil {
			return nil, fmt.Errorf("list user notes: %w", err)
		}
		notes, nextCursor, hasMore, err := parseUserNotesResponse(respBytes)
		if err != nil {
			return nil, fmt.Errorf("parse user notes: %w", err)
		}
		collected = append(collected, notes...)
		if !hasMore || nextCursor == cursor || nextCursor == "" {
			break
		}
		cursor = nextCursor
	}
	if len(collected) > limit {
		collected = collected[:limit]
	}
	return collected, nil
}

// NoteDetail retrieves a note's metadata including image URLs.
func (c *Client) NoteDetail(ctx context.Context, noteID, xsecToken, source string) (*NoteDetail, error) {
	payload := buildNoteDetailPayload(noteID, xsecToken, source)
	respBytes, err := c.requestJSON(ctx, http.MethodPost, "/api/sns/web/v1/feed", payload)
	if err != nil {
		return nil, fmt.Errorf("fetch note detail: %w", err)
	}
	return parseNoteDetail(respBytes)
}

func (c *Client) requestJSON(ctx context.Context, method, api string, payload interface{}) ([]byte, error) {
	headers, body, err := c.buildHeaders(ctx, api, method, payload)
	if err != nil {
		return nil, err
	}

	endpoint := baseURL + api
	var req *http.Request
	if method == http.MethodGet {
		req, err = http.NewRequestWithContext(ctx, method, endpoint, nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	}
	if err != nil {
		return nil, err
	}
	req.Header = headers

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(respBytes))
	}
	return respBytes, nil
}

func (c *Client) buildHeaders(ctx context.Context, api, method string, payload interface{}) (http.Header, []byte, error) {
	var body []byte
	payloadForSign := payload
	if payload != nil {
		var err error
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal payload: %w", err)
		}
		payloadForSign = json.RawMessage(body)
	}

	sig, err := c.signer.Sign(api, method, c.cookies["a1"], payloadForSign)
	if err != nil {
		return nil, nil, err
	}

	tpl := templateHeaders()
	tpl.Set("x-s", sig.Xs)
	tpl.Set("x-t", strconv.FormatInt(sig.Xt, 10))
	tpl.Set("x-s-common", sig.XsCommon)
	tpl.Set("x-b3-traceid", randomTraceID(21))
	tpl.Set("cookie", c.cookieHeader)

	return tpl, body, nil
}

func parseCookies(cookies string) map[string]string {
	result := make(map[string]string)
	segments := strings.Split(cookies, ";")
	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		parts := strings.SplitN(seg, "=", 2)
		if len(parts) != 2 {
			continue
		}
		result[parts[0]] = parts[1]
	}
	return result
}

func formatCookieHeader(cookieMap map[string]string) string {
	pairs := make([]string, 0, len(cookieMap))
	for k, v := range cookieMap {
		pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(pairs, "; ")
}

func templateHeaders() http.Header {
	h := http.Header{}
	h.Set("authority", "edith.xiaohongshu.com")
	h.Set("accept", "application/json, text/plain, */*")
	h.Set("accept-language", "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6")
	h.Set("cache-control", "no-cache")
	h.Set("content-type", "application/json;charset=UTF-8")
	h.Set("origin", "https://www.xiaohongshu.com")
	h.Set("pragma", "no-cache")
	h.Set("referer", "https://www.xiaohongshu.com/")
	h.Set("sec-ch-ua", "\"Not A(Brand\";v=\"99\", \"Microsoft Edge\";v=\"121\", \"Chromium\";v=\"121\"")
	h.Set("sec-ch-ua-mobile", "?0")
	h.Set("sec-ch-ua-platform", "\"Windows\"")
	h.Set("sec-fetch-dest", "empty")
	h.Set("sec-fetch-mode", "cors")
	h.Set("sec-fetch-site", "same-site")
	h.Set("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0")
	h.Set("x-mns", "unload")
	h.Set("x-xray-traceid", randomHex(32))
	return h
}

func randomHex(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		for i := range bytes {
			bytes[i] = byte(time.Now().UnixNano() >> (uint(i) % 8))
		}
	}
	hexAlphabet := []byte("0123456789abcdef")
	for i, b := range bytes {
		bytes[i] = hexAlphabet[int(b)%len(hexAlphabet)]
	}
	return string(bytes)
}

func randomTraceID(length int) string {
	alphabet := []byte("abcdef0123456789")
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		// fallback to time-based entropy on failure
		for i := range bytes {
			bytes[i] = byte(time.Now().UnixNano() >> (uint(i) % 8))
		}
	}
	for i, b := range bytes {
		bytes[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(bytes)
}
