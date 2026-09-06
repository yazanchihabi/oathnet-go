package oathnet

import "encoding/json"

// marshalRequestFields preserves optional maps explicitly supplied as empty.
// Callers pass an alias value to avoid re-entering their MarshalJSON method.
func marshalRequestFields(value interface{}, fields map[string]interface{}) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	for key, value := range fields {
		payload[key] = value
	}
	return json.Marshal(payload)
}
