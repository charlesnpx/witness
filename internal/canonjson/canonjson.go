package canonjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

var jsonNumberPattern = regexp.MustCompile(`^(-?)(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$`)

// Marshal returns the deterministic canonical JSON form used by Witness and
// relay-root-digests-v1 semantic JSON digests.
func Marshal(value any) ([]byte, error) {
	materialized, err := Materialize(value)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	if err := appendCanonical(&buffer, materialized); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// MustMarshal is intended for tests and package-level fixtures.
func MustMarshal(value any) []byte {
	encoded, err := Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}

// Materialize converts ordinary Go values into JSON-shaped values while
// preserving json.Number surface text for exact decimal normalization.
func Materialize(value any) (any, error) {
	switch typed := value.(type) {
	case nil, bool, string, json.Number,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		return typed, nil
	case []any:
		items := make([]any, len(typed))
		for i, item := range typed {
			materialized, err := Materialize(item)
			if err != nil {
				return nil, err
			}
			items[i] = materialized
		}
		return items, nil
	case map[string]any:
		object := make(map[string]any, len(typed))
		for key, item := range typed {
			materialized, err := Materialize(item)
			if err != nil {
				return nil, err
			}
			object[key] = materialized
		}
		return object, nil
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.UseNumber()
		var decoded any
		if err := decoder.Decode(&decoded); err != nil {
			return nil, err
		}
		if decoder.More() {
			return nil, errors.New("canonical JSON materialization produced multiple values")
		}
		return Materialize(decoded)
	}
}

func appendCanonical(buffer *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		buffer.WriteString("null")
	case bool:
		if typed {
			buffer.WriteString("true")
		} else {
			buffer.WriteString("false")
		}
	case string:
		if !utf8.ValidString(typed) {
			return errors.New("canonical JSON strings must be valid UTF-8")
		}
		return appendJSONString(buffer, typed)
	case json.Number:
		normalized, err := normalizeNumber(string(typed))
		if err != nil {
			return err
		}
		buffer.WriteString(normalized)
	case int:
		return appendNumber(buffer, strconv.FormatInt(int64(typed), 10))
	case int8:
		return appendNumber(buffer, strconv.FormatInt(int64(typed), 10))
	case int16:
		return appendNumber(buffer, strconv.FormatInt(int64(typed), 10))
	case int32:
		return appendNumber(buffer, strconv.FormatInt(int64(typed), 10))
	case int64:
		return appendNumber(buffer, strconv.FormatInt(typed, 10))
	case uint:
		return appendNumber(buffer, strconv.FormatUint(uint64(typed), 10))
	case uint8:
		return appendNumber(buffer, strconv.FormatUint(uint64(typed), 10))
	case uint16:
		return appendNumber(buffer, strconv.FormatUint(uint64(typed), 10))
	case uint32:
		return appendNumber(buffer, strconv.FormatUint(uint64(typed), 10))
	case uint64:
		return appendNumber(buffer, strconv.FormatUint(typed, 10))
	case float32:
		return appendFloat(buffer, float64(typed), 32)
	case float64:
		return appendFloat(buffer, typed, 64)
	case []any:
		buffer.WriteByte('[')
		for i, item := range typed {
			if i > 0 {
				buffer.WriteByte(',')
			}
			if err := appendCanonical(buffer, item); err != nil {
				return err
			}
		}
		buffer.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if !utf8.ValidString(key) {
				return errors.New("canonical JSON object keys must be valid UTF-8")
			}
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buffer.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buffer.WriteByte(',')
			}
			if err := appendJSONString(buffer, key); err != nil {
				return err
			}
			buffer.WriteByte(':')
			if err := appendCanonical(buffer, typed[key]); err != nil {
				return err
			}
		}
		buffer.WriteByte('}')
	default:
		return fmt.Errorf("canonical JSON does not support value type %T", value)
	}
	return nil
}

func appendJSONString(buffer *bytes.Buffer, value string) error {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return err
	}
	buffer.Write(bytes.TrimSuffix(encoded.Bytes(), []byte("\n")))
	return nil
}

func appendNumber(buffer *bytes.Buffer, raw string) error {
	normalized, err := normalizeNumber(raw)
	if err != nil {
		return err
	}
	buffer.WriteString(normalized)
	return nil
}

func appendFloat(buffer *bytes.Buffer, value float64, bits int) error {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return errors.New("canonical JSON numbers must be finite")
	}
	return appendNumber(buffer, strconv.FormatFloat(value, 'g', -1, bits))
}

func normalizeNumber(raw string) (string, error) {
	parts := jsonNumberPattern.FindStringSubmatch(raw)
	if parts == nil {
		return "", fmt.Errorf("invalid canonical JSON number %q", raw)
	}
	sign, integer, fraction, exponentText := parts[1], parts[2], parts[3], parts[4]
	digits := integer + fraction
	firstNonZero := strings.IndexFunc(digits, func(r rune) bool {
		return r != '0'
	})
	if firstNonZero < 0 {
		return "0", nil
	}
	significand := strings.TrimRight(digits[firstNonZero:], "0")
	exponent := new(big.Int)
	if exponentText != "" {
		if _, ok := exponent.SetString(exponentText, 10); !ok {
			return "", fmt.Errorf("invalid canonical JSON exponent %q", exponentText)
		}
	}
	exponent.Add(exponent, big.NewInt(int64(len(integer)-firstNonZero-1)))

	var builder strings.Builder
	builder.WriteString(sign)
	builder.WriteByte(significand[0])
	if len(significand) > 1 {
		builder.WriteByte('.')
		builder.WriteString(significand[1:])
	}
	if exponent.Sign() != 0 {
		builder.WriteByte('e')
		builder.WriteString(exponent.String())
	}
	return builder.String(), nil
}
