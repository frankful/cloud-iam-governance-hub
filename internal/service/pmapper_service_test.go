package service

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hibiken/asynq"
	"github.com/frankful/cloud-iam-governance-hub/internal/model"
)

type fakePMapperRunner struct {
	mu             sync.Mutex
	graphJSON      []byte
	importErr      error
	exportErr      error
	importOutput   []byte
	exportOutput   []byte
	commands       [][]string
	importedInput  []byte
	blockUntilDone bool
}

func (runner *fakePMapperRunner) Run(
	ctx context.Context,
	binary string,
	args ...string,
) ([]byte, error) {
	runner.mu.Lock()
	runner.commands = append(runner.commands, append([]string{binary}, args...))
	runner.mu.Unlock()

	if runner.blockUntilDone {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if len(args) == 0 {
		return nil, errors.New("missing CLI command")
	}

	switch args[0] {
	case "import":
		if runner.importErr != nil {
			return runner.importOutput, runner.importErr
		}
		inputPath, err := argumentValue(args, "--input")
		if err != nil {
			return nil, err
		}
		input, err := os.ReadFile(inputPath)
		if err != nil {
			return nil, err
		}
		runner.importedInput = input
		return nil, nil
	case "graph":
		if runner.exportErr != nil {
			return runner.exportOutput, runner.exportErr
		}
		outputPath, err := argumentValue(args, "--output")
		if err != nil {
			return nil, err
		}
		return nil, os.WriteFile(outputPath, runner.graphJSON, 0o600)
	default:
		return nil, errors.New("unexpected PMapper command")
	}
}

type fakeIAMRelationshipRepository struct {
	relationships []model.IAMRelationship
	err           error
	calls         int
}

func (repository *fakeIAMRelationshipRepository) CreateRelationships(
	_ context.Context,
	relationships []model.IAMRelationship,
) error {
	repository.calls++
	if repository.err != nil {
		return repository.err
	}
	repository.relationships = append([]model.IAMRelationship(nil), relationships...)
	return nil
}

func testPMapperService(
	t *testing.T,
	runner PMapperCommandRunner,
	repository IAMRelationshipRepository,
	timeout time.Duration,
) *PMapperGraphService {
	t.Helper()
	service, err := newPMapperGraphService(PMapperConfig{
		Binary:     "pmapper",
		ImportArgs: []string{"import", "--input", inputPathPlaceholder},
		ExportArgs: []string{"graph", "export", "--output", outputPathPlaceholder},
		Timeout:    timeout,
		TempDir:    t.TempDir(),
	}, repository, nil, runner)
	if err != nil {
		t.Fatalf("newPMapperGraphService() error = %v", err)
	}
	return service
}

func testPrincipals() []model.IAMPrincipal {
	return []model.IAMPrincipal{
		{
			ID:            41,
			PrincipalType: "Role",
			PrincipalName: "reports-reader",
			ARN:           "arn:aws:iam::123456789012:role/reports-reader",
			TrustPolicy:   model.JSONB(`{"Version":"2012-10-17"}`),
		},
	}
}

func TestBuildGraphImportsPrincipalsAndPersistsRelationships(t *testing.T) {
	graphJSON := []byte(`{
		"relationships": [
			{
				"principal_arn": "arn:aws:iam::123456789012:role/reports-reader",
				"action": "s3:GetObject",
				"resource": "arn:aws:s3:::reports/*",
				"source": {"node": "reports-reader"}
			}
		]
	}`)
	runner := &fakePMapperRunner{graphJSON: graphJSON}
	repository := &fakeIAMRelationshipRepository{}
	service := testPMapperService(t, runner, repository, time.Second)

	if err := service.BuildGraph(context.Background(), testPrincipals()); err != nil {
		t.Fatalf("BuildGraph() error = %v", err)
	}

	var input []model.IAMPrincipal
	if err := json.Unmarshal(runner.importedInput, &input); err != nil {
		t.Fatalf("decode imported input: %v", err)
	}
	if len(input) != 1 || input[0].ARN != testPrincipals()[0].ARN {
		t.Fatalf("imported principals = %#v", input)
	}
	if len(runner.commands) != 2 || runner.commands[0][1] != "import" || runner.commands[1][1] != "graph" {
		t.Fatalf("PMapper commands = %#v, want import then graph export", runner.commands)
	}
	if repository.calls != 1 || len(repository.relationships) != 1 {
		t.Fatalf("persisted %d relationships in %d repository calls", len(repository.relationships), repository.calls)
	}

	relationship := repository.relationships[0]
	if relationship.PrincipalID == nil || *relationship.PrincipalID != 41 {
		t.Errorf("PrincipalID = %v, want 41", relationship.PrincipalID)
	}
	if relationship.Action != "s3:GetObject" || relationship.Resource != "arn:aws:s3:::reports/*" {
		t.Errorf("relationship action/resource = %q/%q", relationship.Action, relationship.Resource)
	}
	if !json.Valid(relationship.SourceJSON) || !strings.Contains(string(relationship.SourceJSON), `"source"`) {
		t.Errorf("SourceJSON did not preserve raw edge: %s", relationship.SourceJSON)
	}
	if relationship.SyncVersion == nil || *relationship.SyncVersion == "" {
		t.Error("SyncVersion was not set")
	}
	if relationship.CreatedAt.IsZero() {
		t.Error("CreatedAt was not set")
	}
}

func TestBuildGraphAcceptsRelationshipArray(t *testing.T) {
	graphJSON := []byte(`[{
		"principal_arn": "arn:aws:iam::123456789012:role/reports-reader",
		"action": "s3:ListBucket",
		"resource": "arn:aws:s3:::reports"
	}]`)
	repository := &fakeIAMRelationshipRepository{}
	service := testPMapperService(t, &fakePMapperRunner{graphJSON: graphJSON}, repository, time.Second)

	if err := service.BuildGraph(context.Background(), testPrincipals()); err != nil {
		t.Fatalf("BuildGraph() error = %v", err)
	}
	if got := len(repository.relationships); got != 1 {
		t.Fatalf("relationship count = %d, want 1", got)
	}
}

func TestBuildGraphReportsCLIAndPersistenceErrors(t *testing.T) {
	tests := []struct {
		name       string
		runner     *fakePMapperRunner
		repository *fakeIAMRelationshipRepository
		wantError  string
	}{
		{
			name: "import command",
			runner: &fakePMapperRunner{
				importErr:    errors.New("exit status 1"),
				importOutput: []byte("bad input"),
			},
			repository: &fakeIAMRelationshipRepository{},
			wantError:  "PMapper import command failed: exit status 1: bad input",
		},
		{
			name: "export command",
			runner: &fakePMapperRunner{
				exportErr:    errors.New("exit status 2"),
				exportOutput: []byte("export failed"),
			},
			repository: &fakeIAMRelationshipRepository{},
			wantError:  "PMapper graph export command failed: exit status 2: export failed",
		},
		{
			name: "repository",
			runner: &fakePMapperRunner{
				graphJSON: []byte(`[{
					"principal_arn": "arn:aws:iam::123456789012:role/reports-reader",
					"action": "s3:GetObject",
					"resource": "arn:aws:s3:::reports/*"
				}]`),
			},
			repository: &fakeIAMRelationshipRepository{err: errors.New("database unavailable")},
			wantError:  "persist PMapper relationships: database unavailable",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := testPMapperService(t, test.runner, test.repository, time.Second)
			err := service.BuildGraph(context.Background(), testPrincipals())
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("BuildGraph() error = %v, want containing %q", err, test.wantError)
			}
		})
	}
}

func TestBuildGraphRejectsInvalidInputAndOutput(t *testing.T) {
	principals := testPrincipals()
	unknownARN := `[{
		"principal_arn": "arn:aws:iam::123456789012:role/unknown",
		"action": "s3:GetObject",
		"resource": "*"
	}]`
	tests := []struct {
		name       string
		principals []model.IAMPrincipal
		graphJSON  []byte
		wantError  string
	}{
		{
			name:      "empty principals",
			graphJSON: []byte(`[]`),
			wantError: "at least one IAM principal",
		},
		{
			name:       "missing principal ID",
			principals: []model.IAMPrincipal{{ARN: principals[0].ARN}},
			graphJSON:  []byte(`[]`),
			wantError:  "positive ID",
		},
		{
			name:       "malformed export",
			principals: principals,
			graphJSON:  []byte(`{"edges": []}`),
			wantError:  "does not contain a relationships array",
		},
		{
			name:       "unknown principal ARN",
			principals: principals,
			graphJSON:  []byte(unknownARN),
			wantError:  "references unknown principal ARN",
		},
		{
			name:       "missing action",
			principals: principals,
			graphJSON: []byte(`[{
				"principal_arn": "arn:aws:iam::123456789012:role/reports-reader",
				"resource": "*"
			}]`),
			wantError: "must include action and resource",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &fakePMapperRunner{graphJSON: test.graphJSON}
			repository := &fakeIAMRelationshipRepository{}
			service := testPMapperService(t, runner, repository, time.Second)
			err := service.BuildGraph(context.Background(), test.principals)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("BuildGraph() error = %v, want containing %q", err, test.wantError)
			}
			if repository.calls != 0 {
				t.Errorf("repository called %d times for invalid graph", repository.calls)
			}
		})
	}
}

func TestBuildGraphHonorsTimeout(t *testing.T) {
	runner := &fakePMapperRunner{blockUntilDone: true}
	service := testPMapperService(t, runner, &fakeIAMRelationshipRepository{}, 10*time.Millisecond)

	err := service.BuildGraph(context.Background(), testPrincipals())
	if err == nil || !strings.Contains(err.Error(), "timed out or was cancelled") {
		t.Fatalf("BuildGraph() error = %v, want timeout error", err)
	}
}

func TestPMapperTaskCreationAndHandler(t *testing.T) {
	task, err := NewPMapperGraphTask(testPrincipals())
	if err != nil {
		t.Fatalf("NewPMapperGraphTask() error = %v", err)
	}
	if task.Type() != PMapperGraphTaskType {
		t.Fatalf("task type = %q, want %q", task.Type(), PMapperGraphTaskType)
	}

	var payload pMapperGraphTaskPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		t.Fatalf("decode task payload: %v", err)
	}
	if len(payload.Principals) != 1 || payload.Principals[0].ARN != testPrincipals()[0].ARN {
		t.Fatalf("task payload = %#v", payload)
	}

	runner := &fakePMapperRunner{graphJSON: []byte(`[]`)}
	service := testPMapperService(t, runner, &fakeIAMRelationshipRepository{}, time.Second)
	if err := service.HandlePMapperGraphTask(context.Background(), task); err != nil {
		t.Fatalf("HandlePMapperGraphTask() error = %v", err)
	}
}

func TestPMapperTaskValidation(t *testing.T) {
	if _, err := NewPMapperGraphTask(nil); err == nil {
		t.Fatal("NewPMapperGraphTask(nil) expected an error")
	}
	if _, err := NewPMapperGraphService(PMapperConfig{}, nil, nil); err == nil {
		t.Fatal("NewPMapperGraphService() expected invalid config error")
	}

	service := testPMapperService(t, &fakePMapperRunner{}, &fakeIAMRelationshipRepository{}, time.Second)
	if err := service.HandlePMapperGraphTask(context.Background(), nil); err == nil {
		t.Fatal("HandlePMapperGraphTask(nil) expected an error")
	}
	if err := service.HandlePMapperGraphTask(
		context.Background(),
		asynq.NewTask("unexpected:type", []byte(`[]`)),
	); err == nil {
		t.Fatal("HandlePMapperGraphTask() expected wrong-type error")
	}
	if err := service.HandlePMapperGraphTask(
		context.Background(),
		asynq.NewTask(PMapperGraphTaskType, []byte(`invalid`)),
	); err == nil {
		t.Fatal("HandlePMapperGraphTask() expected malformed-payload error")
	}
}

func TestBuildGraphRemovesTemporaryInputAndExportFiles(t *testing.T) {
	tempRoot := t.TempDir()
	runner := &fakePMapperRunner{graphJSON: []byte(`[]`)}
	service, err := newPMapperGraphService(PMapperConfig{
		Binary:     "pmapper",
		ImportArgs: []string{"import", "--input", inputPathPlaceholder},
		ExportArgs: []string{"graph", "export", "--output", outputPathPlaceholder},
		Timeout:    time.Second,
		TempDir:    tempRoot,
	}, &fakeIAMRelationshipRepository{}, nil, runner)
	if err != nil {
		t.Fatalf("newPMapperGraphService() error = %v", err)
	}
	if err := service.BuildGraph(context.Background(), testPrincipals()); err != nil {
		t.Fatalf("BuildGraph() error = %v", err)
	}
	entries, err := os.ReadDir(tempRoot)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary work files remain: %v", filepath.Join(tempRoot, entries[0].Name()))
	}
}

func argumentValue(args []string, name string) (string, error) {
	for index, argument := range args {
		if argument == name && index+1 < len(args) {
			return args[index+1], nil
		}
	}
	return "", errors.New("required CLI argument not found")
}
