package yamlconfig

import (
	"encoding/json"
	"fmt"

	yaml "gopkg.in/yaml.v2"
)

// Convert from YAML to JSON
func Convert(in []byte) ([]byte, error) {
	var data map[interface{}]interface{}
	err := yaml.Unmarshal(in, &data)
	if err != nil {
		return nil, err
	}

	// yaml.Unmarshal returns internal maps as map[interface{}]interface{}.
	// It must be cleaned up before it can be converted to JSON.
	cleaned := cleanupMapValue(data)
	out, err := json.Marshal(cleaned)
	return out, err
}

func cleanupInterfaceArray(in []interface{}) []interface{} {
	res := make([]interface{}, len(in))
	for i, v := range in {
		res[i] = cleanupMapValue(v)
	}
	return res
}

func cleanupInterfaceMap(in map[interface{}]interface{}) map[string]interface{} {
	res := make(map[string]interface{})
	for k, v := range in {
		res[fmt.Sprintf("%v", k)] = cleanupMapValue(v)
	}
	return res
}

func cleanupMapValue(v interface{}) interface{} {
	switch v := v.(type) {
	case []interface{}:
		return cleanupInterfaceArray(v)
	case map[interface{}]interface{}:
		return cleanupInterfaceMap(v)
	case bool:
		return v
	case int:
		return v
	case string:
		return v
	default:
		return fmt.Sprintf("%v", v)
	}
}
