package xhs

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SearchNote represents a minimal note reference returned from search endpoints.
type SearchNote struct {
	ID        string
	XsecToken string
	Source    string
}

// NoteDetail contains the cleaned data required for downloading images.
type NoteDetail struct {
	ID         string
	UserID     string
	Nickname   string
	Title      string
	Tags       []string
	ImageURLs  []string
	UploadedAt time.Time
}

func buildSearchPayload(keyword string, page int) map[string]interface{} {
	return map[string]interface{}{
		"keyword":   keyword,
		"page":      page,
		"page_size": 20,
		"search_id": randomTraceID(21),
		"sort":      "general",
		"note_type": 0,
		"ext_flags": []string{},
		"filters": []map[string]interface{}{
			{"tags": []string{"general"}, "type": "sort_type"},
			{"tags": []string{"不限"}, "type": "filter_note_type"},
			{"tags": []string{"不限"}, "type": "filter_note_time"},
			{"tags": []string{"不限"}, "type": "filter_note_range"},
			{"tags": []string{"不限"}, "type": "filter_pos_distance"},
		},
		"geo":           "",
		"image_formats": []string{"jpg", "webp", "avif"},
	}
}

func buildUserSearchPayload(keyword string, page int) map[string]interface{} {
	return map[string]interface{}{
		"search_user_request": map[string]interface{}{
			"keyword":    keyword,
			"search_id":  randomTraceID(21),
			"page":       page,
			"page_size":  15,
			"biz_type":   "web_search_user",
			"request_id": randomTraceID(22),
		},
	}
}

func buildNoteDetailPayload(noteID, xsecToken, source string) map[string]interface{} {
	if source == "" {
		source = "pc_search"
	}
	return map[string]interface{}{
		"source_note_id": noteID,
		"image_formats":  []string{"jpg", "webp", "avif"},
		"extra": map[string]string{
			"need_body_topic": "1",
		},
		"xsec_source": source,
		"xsec_token":  xsecToken,
	}
}

func parseSearchNotesResponse(data []byte) ([]SearchNote, bool, error) {
	var resp struct {
		Success bool   `json:"success"`
		Msg     string `json:"msg"`
		Data    struct {
			Items []struct {
				ModelType string `json:"model_type"`
				ID        string `json:"id"`
				XsecToken string `json:"xsec_token"`
			} `json:"items"`
			HasMore bool `json:"has_more"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, false, err
	}
	if !resp.Success {
		return nil, false, fmt.Errorf("api error: %s", resp.Msg)
	}
	result := make([]SearchNote, 0, len(resp.Data.Items))
	for _, item := range resp.Data.Items {
		if item.ModelType != "note" {
			continue
		}
		result = append(result, SearchNote{
			ID:        item.ID,
			XsecToken: item.XsecToken,
			Source:    "pc_search",
		})
	}
	return result, resp.Data.HasMore, nil
}

func extractUserIDFromSearch(raw []byte, targetRedID string) (string, bool, error) {
	var resp map[string]interface{}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return "", false, err
	}
	if success, ok := resp["success"].(bool); ok && !success {
		return "", false, fmt.Errorf("api error: %v", resp["msg"])
	}
	data, ok := resp["data"].(map[string]interface{})
	if !ok {
		return "", false, errors.New("unexpected user search payload")
	}
	usersAny, ok := data["users"].([]interface{})
	if !ok {
		return "", false, errors.New("missing users in search payload")
	}
	for _, rawUser := range usersAny {
		userMap, ok := rawUser.(map[string]interface{})
		if !ok {
			continue
		}
		redID := pickString(userMap, "red_id")
		if redID == "" {
			if basic, ok := userMap["basic_info"].(map[string]interface{}); ok {
				redID = pickString(basic, "red_id")
			}
		}
		if redID != targetRedID {
			continue
		}
		candidate := pickString(userMap, "user_id")
		if candidate == "" {
			if basic, ok := userMap["basic_info"].(map[string]interface{}); ok {
				candidate = pickString(basic, "user_id")
			}
		}
		if candidate == "" {
			candidate = pickString(userMap, "id")
		}
		return candidate, data["has_more"].(bool), nil
	}
	hasMore, _ := data["has_more"].(bool)
	return "", hasMore, nil
}

func parseUserNotesResponse(data []byte) ([]SearchNote, string, bool, error) {
	var resp struct {
		Success bool   `json:"success"`
		Msg     string `json:"msg"`
		Data    struct {
			Notes []struct {
				NoteID     string `json:"note_id"`
				XsecToken  string `json:"xsec_token"`
				XsecSource string `json:"xsec_source"`
			} `json:"notes"`
			Cursor  string `json:"cursor"`
			HasMore bool   `json:"has_more"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, "", false, err
	}
	if !resp.Success {
		return nil, "", false, fmt.Errorf("api error: %s", resp.Msg)
	}
	items := make([]SearchNote, 0, len(resp.Data.Notes))
	for _, n := range resp.Data.Notes {
		items = append(items, SearchNote{
			ID:        n.NoteID,
			XsecToken: n.XsecToken,
			Source:    n.XsecSource,
		})
	}
	return items, resp.Data.Cursor, resp.Data.HasMore, nil
}

func parseNoteDetail(data []byte) (*NoteDetail, error) {
	var resp struct {
		Success bool   `json:"success"`
		Msg     string `json:"msg"`
		Data    struct {
			Items []struct {
				ID       string `json:"id"`
				NoteCard struct {
					Type  string `json:"type"`
					Title string `json:"title"`
					Time  int64  `json:"time"`
					User  struct {
						UserID   string `json:"user_id"`
						Nickname string `json:"nickname"`
					} `json:"user"`
					ImageList []struct {
						InfoList []struct {
							URL string `json:"url"`
						} `json:"info_list"`
					} `json:"image_list"`
					TagList []struct {
						Name string `json:"name"`
					} `json:"tag_list"`
				} `json:"note_card"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, err
	}
	if !resp.Success {
		return nil, fmt.Errorf("api error: %s", resp.Msg)
	}
	if len(resp.Data.Items) == 0 {
		return nil, errors.New("note detail payload missing items")
	}
	note := resp.Data.Items[0]
	imageURLs := make([]string, 0, len(note.NoteCard.ImageList))
	for _, img := range note.NoteCard.ImageList {
		for _, info := range img.InfoList {
			if info.URL != "" {
				imageURLs = append(imageURLs, info.URL)
				break
			}
		}
	}
	tags := make([]string, 0, len(note.NoteCard.TagList))
	for _, tag := range note.NoteCard.TagList {
		tags = append(tags, tag.Name)
	}
	return &NoteDetail{
		ID:         note.ID,
		UserID:     note.NoteCard.User.UserID,
		Nickname:   note.NoteCard.User.Nickname,
		Title:      note.NoteCard.Title,
		Tags:       tags,
		ImageURLs:  imageURLs,
		UploadedAt: time.UnixMilli(note.NoteCard.Time),
	}, nil
}

func pickString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
