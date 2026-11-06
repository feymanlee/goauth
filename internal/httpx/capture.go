package httpx

import (
	"bytes"
	"encoding/json"
)

type capturedResponse struct {
	target any
	raw    *map[string]any
}

func Capture(target any, raw *map[string]any) json.Unmarshaler {
	return &capturedResponse{target: target, raw: raw}
}

func (response *capturedResponse) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, response.target); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return decoder.Decode(response.raw)
}
