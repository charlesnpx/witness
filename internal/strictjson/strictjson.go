package strictjson

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/charlesnpx/witness/internal/diag"
)

// DefaultMaxBytes is the default per-document or per-line input ceiling used
// by the strict JSON reader when callers do not provide a positive limit.
const DefaultMaxBytes int64 = 1 << 20

// Int64 accepts canonical JSON numbers that are mathematically integral and
// fit in int64, including Witness canonical exponent form such as 2.578e3.
type Int64 int64

// Int is the machine-int counterpart to Int64 for Witness-owned canonical
// artifacts with integer count fields.
type Int int

func (value *Int64) UnmarshalJSON(data []byte) error {
	parsed, err := ParseInt64JSON(data)
	if err != nil {
		return err
	}
	*value = Int64(parsed)
	return nil
}

func (value *Int) UnmarshalJSON(data []byte) error {
	parsed, err := ParseIntJSON(data)
	if err != nil {
		return err
	}
	*value = Int(parsed)
	return nil
}

func ParseInt64JSON(data []byte) (int64, error) {
	text, err := jsonNumberText(data)
	if err != nil {
		return 0, err
	}
	return parseIntegralInt64(text)
}

func ParseIntJSON(data []byte) (int, error) {
	parsed, err := ParseInt64JSON(data)
	if err != nil {
		return 0, err
	}
	max := int64(^uint(0) >> 1)
	min := -max - 1
	if parsed < min || parsed > max {
		return 0, fmt.Errorf("JSON integer %d is out of range for int", parsed)
	}
	return int(parsed), nil
}

func Decode[T any](reader io.Reader, maxBytes int64) (T, error) {
	data, err := readLimited(reader, effectiveLimit(maxBytes))
	if err != nil {
		var zero T
		return zero, err
	}
	return DecodeBytes[T](data, maxBytes)
}

func DecodeBytes[T any](data []byte, maxBytes int64) (T, error) {
	var zero T
	limit := effectiveLimit(maxBytes)
	if int64(len(data)) > limit {
		return zero, diag.New(
			diag.CodeJSONTooLarge,
			"JSON input exceeds the configured size limit.",
			diag.WithDetail("limit_bytes", limit),
			diag.WithDetail("size_bytes", len(data)),
		)
	}
	if err := validateStrict(data); err != nil {
		return zero, err
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	var result T
	if err := decoder.Decode(&result); err != nil {
		return zero, typedDecodeError(decoder, err)
	}
	if code, offset := trailingContent(data, decoder.InputOffset()); code != "" {
		return zero, trailingError(code, offset)
	}
	return result, nil
}

func DecodeAny(reader io.Reader, maxBytes int64) (any, error) {
	return Decode[any](reader, maxBytes)
}

func DecodeAnyBytes(data []byte, maxBytes int64) (any, error) {
	return DecodeBytes[any](data, maxBytes)
}

func DecodeJSONL[T any](reader io.Reader, maxBytes int64) ([]T, error) {
	buffered := bufio.NewReader(reader)
	limit := effectiveLimit(maxBytes)
	var records []T
	for lineNumber := 1; ; lineNumber++ {
		line, err := readLineLimited(buffered, limit)
		if len(line) > 0 {
			line = bytes.TrimSuffix(line, []byte("\n"))
			line = bytes.TrimSuffix(line, []byte("\r"))
			record, decodeErr := DecodeBytes[T](line, limit)
			if decodeErr != nil {
				return nil, withLine(decodeErr, lineNumber)
			}
			records = append(records, record)
		}
		if err == nil {
			continue
		}
		if err == io.EOF {
			return records, nil
		}
		return nil, err
	}
}

func readLineLimited(reader *bufio.Reader, limit int64) ([]byte, error) {
	var line []byte
	for {
		part, err := reader.ReadSlice('\n')
		line = append(line, part...)
		if int64(len(bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r")))) > limit {
			return nil, diag.New(
				diag.CodeJSONTooLarge,
				"JSONL line exceeds the configured size limit.",
				diag.WithDetail("limit_bytes", limit),
				diag.WithDetail("size_bytes", len(line)),
			)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return line, err
	}
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	var buffer bytes.Buffer
	read, err := buffer.ReadFrom(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if read > limit {
		return nil, diag.New(
			diag.CodeJSONTooLarge,
			"JSON input exceeds the configured size limit.",
			diag.WithDetail("limit_bytes", limit),
			diag.WithDetail("size_bytes", read),
		)
	}
	return buffer.Bytes(), nil
}

func effectiveLimit(maxBytes int64) int64 {
	if maxBytes > 0 {
		return maxBytes
	}
	return DefaultMaxBytes
}

func jsonNumberText(data []byte) (string, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return "", fmt.Errorf("JSON integer must be a number")
	}
	switch trimmed[0] {
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
	default:
		return "", fmt.Errorf("JSON integer must be a number")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.UseNumber()
	var number json.Number
	if err := decoder.Decode(&number); err != nil {
		return "", fmt.Errorf("JSON integer must be a number: %w", err)
	}
	if code, offset := trailingContent(trimmed, decoder.InputOffset()); code != "" {
		return "", fmt.Errorf("JSON integer has trailing content at offset %d", offset)
	}
	return number.String(), nil
}

func parseIntegralInt64(text string) (int64, error) {
	negative := strings.HasPrefix(text, "-")
	if negative {
		text = strings.TrimPrefix(text, "-")
	}
	mantissa := text
	exponentText := ""
	if index := strings.IndexAny(text, "eE"); index >= 0 {
		mantissa = text[:index]
		exponentText = text[index+1:]
	}
	integer := mantissa
	fraction := ""
	if index := strings.IndexByte(mantissa, '.'); index >= 0 {
		integer = mantissa[:index]
		fraction = mantissa[index+1:]
	}

	significant := strings.TrimLeft(integer+fraction, "0")
	if significant == "" {
		return 0, nil
	}

	exponent := new(big.Int)
	if exponentText != "" {
		normalized := strings.TrimPrefix(exponentText, "+")
		if _, ok := exponent.SetString(normalized, 10); !ok {
			return 0, fmt.Errorf("JSON integer exponent is invalid")
		}
	}
	shift := new(big.Int).Sub(exponent, big.NewInt(int64(len(fraction))))
	switch shift.Sign() {
	case -1:
		places := new(big.Int).Neg(shift)
		if places.Cmp(big.NewInt(int64(len(significant)))) > 0 {
			return 0, fmt.Errorf("JSON number %q is not an integer", text)
		}
		cut := int(places.Int64())
		if cut > 0 {
			suffix := significant[len(significant)-cut:]
			if strings.Trim(suffix, "0") != "" {
				return 0, fmt.Errorf("JSON number %q is not an integer", text)
			}
			significant = significant[:len(significant)-cut]
			if significant == "" {
				return 0, nil
			}
		}
	case 1:
		if shift.Cmp(big.NewInt(19)) > 0 {
			return 0, fmt.Errorf("JSON integer %q is out of range for int64", text)
		}
		places := int(shift.Int64())
		if len(significant)+places > 19 {
			return 0, fmt.Errorf("JSON integer %q is out of range for int64", text)
		}
		significant += strings.Repeat("0", places)
	}
	if len(significant) > 19 {
		return 0, fmt.Errorf("JSON integer %q is out of range for int64", text)
	}
	if negative {
		significant = "-" + significant
	}
	parsed, err := strconv.ParseInt(significant, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("JSON integer %q is out of range for int64", text)
	}
	return parsed, nil
}

func validateStrict(data []byte) error {
	if offset := firstInvalidUTF8(data); offset >= 0 {
		return diag.New(
			diag.CodeInvalidUTF8,
			"JSON input must be valid UTF-8.",
			diag.WithDetail("offset", offset),
		)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkValue(decoder, ""); err != nil {
		return err
	}
	if code, offset := trailingContent(data, decoder.InputOffset()); code != "" {
		return trailingError(code, offset)
	}
	return nil
}

func walkValue(decoder *json.Decoder, path string) error {
	token, err := decoder.Token()
	if err != nil {
		return syntaxError(decoder, path, err)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}

	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return syntaxError(decoder, path, err)
			}
			key, ok := keyToken.(string)
			if !ok {
				return diag.New(diag.CodeInvalidJSON, "JSON object keys must be strings.", diag.WithPath(path))
			}
			keyPath := appendPointer(path, key)
			if _, exists := seen[key]; exists {
				return diag.New(
					diag.CodeDuplicateJSONKey,
					"JSON objects must not contain duplicate keys.",
					diag.WithPath(keyPath),
					diag.WithDetail("key", key),
				)
			}
			seen[key] = struct{}{}
			if err := walkValue(decoder, keyPath); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return syntaxError(decoder, path, err)
		}
		if closing != json.Delim('}') {
			return diag.New(diag.CodeInvalidJSON, "JSON object is not properly closed.", diag.WithPath(path))
		}
	case '[':
		for index := 0; decoder.More(); index++ {
			if err := walkValue(decoder, appendPointer(path, strconv.Itoa(index))); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return syntaxError(decoder, path, err)
		}
		if closing != json.Delim(']') {
			return diag.New(diag.CodeInvalidJSON, "JSON array is not properly closed.", diag.WithPath(path))
		}
	default:
		return diag.New(diag.CodeInvalidJSON, "JSON contains an unexpected closing delimiter.", diag.WithPath(path))
	}
	return nil
}

func trailingContent(data []byte, offset int64) (string, int) {
	index := int(offset)
	if index < 0 {
		index = 0
	}
	if index > len(data) {
		index = len(data)
	}
	for index < len(data) {
		switch data[index] {
		case ' ', '\t', '\r', '\n':
			index++
		default:
			if beginsJSONValue(data[index:]) {
				return diag.CodeTrailingJSONValue, index
			}
			return diag.CodeTrailingJSONGarbage, index
		}
	}
	return "", -1
}

func beginsJSONValue(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	return decoder.Decode(&value) == nil
}

func trailingError(code string, offset int) error {
	message := "JSON input must contain exactly one top-level value."
	if code == diag.CodeTrailingJSONGarbage {
		message = "JSON input contains non-whitespace trailing garbage."
	}
	return diag.New(code, message, diag.WithDetail("offset", offset))
}

func typedDecodeError(decoder *json.Decoder, err error) error {
	if field, ok := unknownField(err); ok {
		return diag.Wrap(
			err,
			diag.CodeUnknownJSONField,
			"JSON input contains a field not declared by the target type.",
			diag.WithDetail("field", field),
		)
	}
	return syntaxError(decoder, "", err)
}

func syntaxError(decoder *json.Decoder, path string, err error) error {
	return diag.Wrap(
		err,
		diag.CodeInvalidJSON,
		"JSON input is not syntactically valid.",
		diag.WithPath(path),
		diag.WithDetail("offset", decoder.InputOffset()),
		diag.WithDetail("error", err.Error()),
	)
}

func unknownField(err error) (string, bool) {
	const prefix = "json: unknown field "
	if !strings.HasPrefix(err.Error(), prefix) {
		return "", false
	}
	quoted := strings.TrimPrefix(err.Error(), prefix)
	field, unquoteErr := strconv.Unquote(quoted)
	if unquoteErr != nil {
		return quoted, true
	}
	return field, true
}

func appendPointer(path string, segment string) string {
	escaped := strings.ReplaceAll(segment, "~", "~0")
	escaped = strings.ReplaceAll(escaped, "/", "~1")
	return fmt.Sprintf("%s/%s", path, escaped)
}

func firstInvalidUTF8(data []byte) int {
	for offset := 0; offset < len(data); {
		r, size := utf8.DecodeRune(data[offset:])
		if r == utf8.RuneError && size == 1 {
			return offset
		}
		offset += size
	}
	return -1
}

func withLine(err error, lineNumber int) error {
	diagnostic := diag.FromError(err)
	return diag.Wrap(
		err,
		diagnostic.Code,
		diagnostic.Message,
		diag.WithPath(fmt.Sprintf("/%d%s", lineNumber, diagnostic.Path)),
		diag.WithDetails(diagnostic.Details),
	)
}
