package service

import (
	"strings"
	"testing"
)

func TestEntryCredentialSourceNamesTheLookupPath(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		profile string
		want    []string
		notWant []string
	}{
		{
			name:    "empty profile falls back to the default chain",
			profile: "",
			want:    []string{"default chain", "instance role"},
		},
		{
			name:    "whitespace-only profile is treated as unset",
			profile: "   ",
			want:    []string{"default chain"},
			notWant: []string{`profile ""`},
		},
		{
			name:    "named profile is quoted and mentions AWS_PROFILE",
			profile: " iam-hub ",
			want:    []string{`profile "iam-hub"`, "AWS_PROFILE"},
			notWant: []string{" iam-hub "},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := EntryCredentialSource(tc.profile)
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("EntryCredentialSource(%q) = %q, missing %q", tc.profile, got, want)
				}
			}
			for _, notWant := range tc.notWant {
				if strings.Contains(got, notWant) {
					t.Fatalf("EntryCredentialSource(%q) = %q, should not contain %q", tc.profile, got, notWant)
				}
			}
		})
	}
}

func TestEntryCredentialHintPointsAtTheOnboardingDoc(t *testing.T) {
	t.Parallel()

	got := EntryCredentialHint("iam-hub")
	if !strings.Contains(got, "docs/aws-credential-setup.md") {
		t.Fatalf("hint should point at the onboarding doc, got %q", got)
	}
	if !strings.Contains(got, `profile "iam-hub"`) {
		t.Fatalf("hint should repeat which source was tried, got %q", got)
	}
}
