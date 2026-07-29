package diag

import (
	"errors"
	"fmt"
	"io"
	"sort"

	"witness/internal/canonjson"
)

const (
	CodeInvalidCommand       = "invalid_command"
	CodeNotImplemented       = "not_implemented"
	CodeJSONTooLarge         = "json_too_large"
	CodeInvalidUTF8          = "invalid_utf8"
	CodeInvalidJSON          = "invalid_json"
	CodeDuplicateJSONKey     = "duplicate_json_key"
	CodeTrailingJSONValue    = "trailing_json_value"
	CodeTrailingJSONGarbage  = "trailing_json_garbage"
	CodeUnknownJSONField     = "unknown_json_field"
	CodeUnsupportedDigest    = "unsupported_digest_class"
	CodeUnsupportedRootKind  = "unsupported_root_artifact_kind"
	CodeInvalidDigestPayload = "invalid_digest_payload"
)

type Diagnostic struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Path    string         `json:"path,omitempty"`
	Details map[string]any `json:"details,omitempty"`
}

type Error struct {
	Diagnostic Diagnostic
	Cause      error
}

type Option func(*Diagnostic)

func New(code string, message string, options ...Option) *Error {
	diagnostic := Diagnostic{Code: code, Message: message}
	for _, option := range options {
		option(&diagnostic)
	}
	return &Error{Diagnostic: diagnostic}
}

func Wrap(cause error, code string, message string, options ...Option) *Error {
	err := New(code, message, options...)
	err.Cause = cause
	return err
}

func WithPath(path string) Option {
	return func(diagnostic *Diagnostic) {
		diagnostic.Path = path
	}
}

func WithDetail(key string, value any) Option {
	return func(diagnostic *Diagnostic) {
		if diagnostic.Details == nil {
			diagnostic.Details = map[string]any{}
		}
		diagnostic.Details[key] = value
	}
}

func WithDetails(details map[string]any) Option {
	return func(diagnostic *Diagnostic) {
		if len(details) == 0 {
			return
		}
		diagnostic.Details = map[string]any{}
		for key, value := range details {
			diagnostic.Details[key] = value
		}
	}
}

func (err *Error) Error() string {
	if err == nil {
		return ""
	}
	if err.Diagnostic.Path != "" {
		return fmt.Sprintf("%s at %s: %s", err.Diagnostic.Code, err.Diagnostic.Path, err.Diagnostic.Message)
	}
	return fmt.Sprintf("%s: %s", err.Diagnostic.Code, err.Diagnostic.Message)
}

func (err *Error) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Cause
}

func FromError(err error) Diagnostic {
	var diagnosticError *Error
	if errors.As(err, &diagnosticError) {
		return diagnosticError.Diagnostic
	}
	return Diagnostic{
		Code:    "internal_error",
		Message: err.Error(),
	}
}

func Sort(diagnostics []Diagnostic) {
	sort.SliceStable(diagnostics, func(i, j int) bool {
		if diagnostics[i].Code != diagnostics[j].Code {
			return diagnostics[i].Code < diagnostics[j].Code
		}
		if diagnostics[i].Path != diagnostics[j].Path {
			return diagnostics[i].Path < diagnostics[j].Path
		}
		return diagnostics[i].Message < diagnostics[j].Message
	})
}

func CanonicalBytes(value any) ([]byte, error) {
	return canonjson.Marshal(value)
}

func WriteCanonical(writer io.Writer, value any) error {
	encoded, err := canonjson.Marshal(value)
	if err != nil {
		return err
	}
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	_, err = writer.Write([]byte("\n"))
	return err
}
