package preflight

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charlesnpx/witness/internal/canonjson"
	"github.com/charlesnpx/witness/internal/digest"
	"github.com/charlesnpx/witness/internal/freeze"
	"github.com/charlesnpx/witness/internal/strictjson"
)

const (
	RefObservationFile = "ref-observation.json"

	RefDriftCheckpointAdjudicate RefDriftCheckpoint = "adjudicate"
	RefDriftCheckpointMetrics    RefDriftCheckpoint = "metrics"
)

type RefDriftCheckpoint string

type retainedArtifactEnvelope struct {
	SchemaVersion string          `json:"schema_version"`
	DigestProfile string          `json:"digest_profile"`
	PayloadDigest string          `json:"payload_digest"`
	Payload       json.RawMessage `json:"payload"`
}

func RetainRefObservation(stateDir string, observation freeze.RefObservation) (string, error) {
	if err := freeze.ValidateRefObservation(observation); err != nil {
		return "", fmt.Errorf("invalid ref observation: %w", err)
	}
	return retain(stateDir, RefObservationFile, observation)
}

func RefObservationDigest(observation freeze.RefObservation) (string, error) {
	if err := freeze.ValidateRefObservation(observation); err != nil {
		return "", err
	}
	payload, err := canonjson.Marshal(observation)
	if err != nil {
		return "", err
	}
	return digest.RawBytes(payload), nil
}

func RefDriftDigest(status freeze.RefDrift) (string, error) {
	if err := freeze.ValidateRefDrift(status); err != nil {
		return "", err
	}
	payload, err := canonjson.Marshal(status)
	if err != nil {
		return "", err
	}
	return digest.RawBytes(payload), nil
}

// RetainRefDrift records a checkpoint-specific freshness fact without
// mutating digest-bound adjudication or metrics documents.
func RetainRefDrift(stateDir string, checkpoint RefDriftCheckpoint, status freeze.RefDrift) (string, error) {
	relativePath, err := refDriftFile(checkpoint)
	if err != nil {
		return "", err
	}
	if err := freeze.ValidateRefDrift(status); err != nil {
		return "", fmt.Errorf("invalid ref drift: %w", err)
	}
	return retain(stateDir, relativePath, status)
}

func ReadRefObservation(path string) (freeze.RefObservation, error) {
	envelope, err := readRetainedArtifactEnvelope(path)
	if err != nil {
		return freeze.RefObservation{}, err
	}
	observation, err := strictjson.DecodeBytes[freeze.RefObservation](envelope.Payload, strictjson.DefaultMaxBytes)
	if err != nil {
		return freeze.RefObservation{}, err
	}
	if err := validateRetainedArtifactPayload(envelope, observation); err != nil {
		return freeze.RefObservation{}, fmt.Errorf("retained ref observation: %w", err)
	}
	if err := freeze.ValidateRefObservation(observation); err != nil {
		return freeze.RefObservation{}, err
	}
	return observation, nil
}

func ReadRefDrift(path string) (freeze.RefDrift, error) {
	envelope, err := readRetainedArtifactEnvelope(path)
	if err != nil {
		return freeze.RefDrift{}, err
	}
	status, err := strictjson.DecodeBytes[freeze.RefDrift](envelope.Payload, strictjson.DefaultMaxBytes*4)
	if err != nil {
		return freeze.RefDrift{}, err
	}
	if err := validateRetainedArtifactPayload(envelope, status); err != nil {
		return freeze.RefDrift{}, fmt.Errorf("retained ref drift: %w", err)
	}
	if err := freeze.ValidateRefDrift(status); err != nil {
		return freeze.RefDrift{}, err
	}
	return status, nil
}

func CheckRefDrift(ctx context.Context, observationPath string) freeze.RefDrift {
	if strings.TrimSpace(observationPath) == "" {
		return freeze.UnavailableRefDrift(freeze.UnavailableRefObservation("", "ref_observation_not_provided"), "ref_observation_not_provided")
	}
	observation, err := ReadRefObservation(observationPath)
	if err != nil {
		return freeze.UnavailableRefDrift(freeze.UnavailableRefObservation("", "ref_observation_unreadable"), "ref_observation_unreadable")
	}
	return freeze.CompareRefObservation(ctx, observation)
}

func RefObservationPath(stateDir string) string {
	return filepath.Join(stateDir, RefObservationFile)
}

func RefDriftPath(stateDir string, checkpoint RefDriftCheckpoint) (string, error) {
	relativePath, err := refDriftFile(checkpoint)
	if err != nil {
		return "", err
	}
	return filepath.Join(stateDir, relativePath), nil
}

func refDriftFile(checkpoint RefDriftCheckpoint) (string, error) {
	switch checkpoint {
	case RefDriftCheckpointAdjudicate:
		return "ref-drift-adjudicate.json", nil
	case RefDriftCheckpointMetrics:
		return "ref-drift-metrics.json", nil
	default:
		return "", fmt.Errorf("unsupported ref drift checkpoint %q", checkpoint)
	}
}

func readRetainedArtifactEnvelope(path string) (retainedArtifactEnvelope, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return retainedArtifactEnvelope{}, err
	}
	envelope, err := strictjson.DecodeBytes[retainedArtifactEnvelope](data, strictjson.DefaultMaxBytes*4)
	if err != nil {
		return retainedArtifactEnvelope{}, err
	}
	if envelope.SchemaVersion != "witness-retained-artifact-v1" || envelope.DigestProfile != digest.Profile {
		return retainedArtifactEnvelope{}, fmt.Errorf("retained artifact envelope is unsupported")
	}
	return envelope, nil
}

func validateRetainedArtifactPayload(envelope retainedArtifactEnvelope, payload any) error {
	payloadBytes, err := canonjson.Marshal(payload)
	if err != nil {
		return err
	}
	if digest.RawBytes(payloadBytes) != strings.TrimSpace(envelope.PayloadDigest) {
		return fmt.Errorf("payload digest mismatch")
	}
	return nil
}
