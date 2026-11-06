package httpx

import (
	"encoding/json"
	"errors"
	"strconv"
)

type Identifier string

func (identifier *Identifier) UnmarshalJSON(data []byte) error {
	var text string
	if len(data) > 0 && data[0] == '"' {
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
	} else {
		if len(data) == 0 {
			return errors.New("invalid identifier")
		}
		for _, character := range data {
			if character < '0' || character > '9' {
				return errors.New("invalid identifier")
			}
		}
		text = string(data)
	}
	*identifier = Identifier(text)
	return nil
}

type Int64 int64

func (value *Int64) UnmarshalJSON(data []byte) error {
	text := string(data)
	if len(data) > 0 && data[0] == '"' {
		if err := json.Unmarshal(data, &text); err != nil {
			return err
		}
	}
	number, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return err
	}
	*value = Int64(number)
	return nil
}
