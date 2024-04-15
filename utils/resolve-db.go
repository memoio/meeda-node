package utils

import "strings"

func TypeByExtension(ext string) string {
	// Set default to "application/octet-stream".
	contentType := "application/octet-stream"
	if ext != "" {
		if content, ok := DB[strings.ToLower(strings.TrimPrefix(ext, "."))]; ok {
			contentType = content.ContentType
		}
	}
	return contentType
}
