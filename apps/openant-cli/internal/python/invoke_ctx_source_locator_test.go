package python

import "testing"

func TestDecodeEnvelopeAcceptsPrettyPrintedSingleDocument(t *testing.T) {
	envelope, err := DecodeEnvelope("{\n  \"status\": \"success\",\n  \"data\": {\"state\": \"INTAKE\"},\n  \"errors\": []\n}\n")
	if err != nil {
		t.Fatalf("DecodeEnvelope() error = %v", err)
	}
	if envelope.Status != "success" {
		t.Fatalf("status = %q, want success", envelope.Status)
	}
}

func TestDecodeEnvelopeRejectsEmptyAndTrailingOutput(t *testing.T) {
	for _, raw := range []string{"", "{} {}", "{\"status\":\"success\"} trailing"} {
		if _, err := DecodeEnvelope(raw); err == nil {
			t.Fatalf("DecodeEnvelope(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestDecodeEnvelopeRejectsUnknownStatus(t *testing.T) {
	if _, err := DecodeEnvelope(`{"status":"partial","data":{},"errors":[]}`); err == nil {
		t.Fatal("unknown status unexpectedly accepted")
	}
}
