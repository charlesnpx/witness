package strictjson

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/charlesnpx/witness/internal/diag"
)

// DefaultMaxBytes is the default per-document or per-line input ceiling used
// by the strict JSON reader when callers do not provide a positive limit.
const DefaultMaxBytes int64 = 1 << 20

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
