package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"spider_xhs/internal/config"
	"spider_xhs/internal/downloader"
	"spider_xhs/internal/signature"
	"spider_xhs/internal/xhs"
)

func main() {
	ctx := context.Background()
	cookies, err := config.LoadCookiesFromEnv()
	if err != nil {
		log.Fatalf("load cookies: %v", err)
	}

	signer := signature.NewSigner(filepath.Join("scripts", "sign_bridge.js"))
	client, err := xhs.NewClient(cookies, signer)
	if err != nil {
		log.Fatalf("init client: %v", err)
	}

	keyword := "新年"
	userRedID := "95694573388"
	limit := 5

	fmt.Printf("Searching notes for keyword %s...\n", keyword)
	notes, err := client.SearchNotes(ctx, keyword, limit)
	if err != nil {
		log.Fatalf("search notes: %v", err)
	}
	fmt.Printf("Found %d notes.\n", len(notes))

	fmt.Printf("Resolving user id for red-id %s...\n", userRedID)
	userID, err := client.SearchUserByRedID(ctx, userRedID)
	if err != nil {
		log.Fatalf("resolve user: %v", err)
	}
	fmt.Printf("Resolved user id: %s\n", userID)

	fmt.Println("Fetching user notes...")
	userNotes, err := client.FetchUserNotes(ctx, userID, limit)
	if err != nil {
		log.Fatalf("user notes: %v", err)
	}
	fmt.Printf("User has %d candidate notes.\n", len(userNotes))

	allNotes := append(notes, userNotes...)
	if len(allNotes) == 0 {
		log.Fatalf("no notes available to download")
	}

	downloadRoot := filepath.Join("datas", "media_datas", time.Now().Format("20060102_150405"))
	for idx, note := range allNotes {
		detail, err := client.NoteDetail(ctx, note.ID, note.XsecToken, note.Source)
		if err != nil {
			log.Printf("note %s detail failed: %v", note.ID, err)
			continue
		}

		noteDir := filepath.Join(downloadRoot, sanitize(detail.Nickname), detail.ID)
		for imgIdx, imgURL := range detail.ImageURLs {
			filename := fmt.Sprintf("%02d_%02d.jpg", idx, imgIdx)
			if _, err := downloader.SaveImage(imgURL, noteDir, filename); err != nil {
				log.Printf("download image %s: %v", imgURL, err)
			}
		}

		metaPath := filepath.Join(noteDir, "meta.json")
		if err := os.WriteFile(metaPath, mustJSON(detail), 0o644); err != nil {
			log.Printf("write meta for %s: %v", detail.ID, err)
		}
	}

	fmt.Printf("Images saved under %s\n", downloadRoot)
}

func sanitize(value string) string {
	replacer := strings.NewReplacer("\\", "_", "/", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", " ", "_")
	return replacer.Replace(value)
}

func mustJSON(v interface{}) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return b
}
