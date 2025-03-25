package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "valid API key",
			headers:     http.Header{"Authorization": []string{"ApiKey abc123"}},
			expectedKey: "abc123",
			expectedErr: nil,
		},
		{
			name:        "no Authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "malformed Authorization header",
			headers:     http.Header{"Authorization": []string{"Bearer abc123"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "empty Authorization header",
			headers:     http.Header{"Authorization": []string{""}},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "multiple Authorization headers",
			headers:     http.Header{"Authorization": []string{"ApiKey abc123", "ApiKey xyz456"}},
			expectedKey: "abc123", // the first one should be considered
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			if gotKey != tt.expectedKey {
				t.Errorf("GetAPIKey() got = %v, want %v", gotKey, tt.expectedKey)
			}
			if gotErr != nil && gotErr.Error() != tt.expectedErr.Error() {
				t.Errorf("GetAPIKey() gotErr = %v, want %v", gotErr, tt.expectedErr)
			}
		})
	}
}
