package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr string
	}{
		{
			name: "Success: Valid ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey secret-token-123"},
			},
			expectedKey: "secret-token-123",
			expectedErr: "",
		},
		{
			name:        "Error: Missing Authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name: "Error: Malformed (Missing prefix)",
			headers: http.Header{
				"Authorization": []string{"wrong-prefix secret-token-123"},
			},
			expectedKey: "",
			expectedErr: "malformed authorization header",
		},
		{
			name: "Error: Malformed (Bearer instead of ApiKey)",
			headers: http.Header{
				"Authorization": []string{"Bearer some-jwt-token"},
			},
			expectedKey: "",
			expectedErr: "malformed authorization header",
		},
		{
			name: "Error: Malformed (Only prefix, no key)",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			expectedErr: "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			// Check the returned key
			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			// Check the error message
			if tt.expectedErr == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error %q, got nil", tt.expectedErr)
				} else if err.Error() != tt.expectedErr {
					t.Errorf("expected error %q, got %q", tt.expectedErr, err.Error())
				}
			}
		})
	}
}
