package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name: "valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			wantKey: "abc123",
			wantErr: nil,
		},
		{
			name:    "missing Authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header (wrong prefix)",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "malformed header (no key provided)",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
			}

			if (err != nil && tt.wantErr == nil) || (err == nil && tt.wantErr != nil) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			} else if err != nil && tt.wantErr != nil && !strings.Contains(err.Error(), tt.wantErr.Error()) {
				t.Errorf("expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}
