package service

import (
	"fmt"
	"strings"
)

// EntryCredentialSource names where the AWS SDK will look for the credential
// that performs sts:AssumeRole. It describes the shape of the source only —
// never the credential itself — so it is safe to log at startup.
//
// Keep this in sync with docs/aws-credential-setup.md §2: the onboarding doc is
// the first place an operator looks when "add account" fails, and a wrong hint
// here sends them to the wrong chapter.
func EntryCredentialSource(profile string) string {
	if trimmed := strings.TrimSpace(profile); trimmed != "" {
		return fmt.Sprintf("shared config profile %q (AWS_PROFILE)", trimmed)
	}
	return "AWS SDK default chain (env vars, shared default profile, container/instance role)"
}

// EntryCredentialHint appends "where we looked, and where to read more" to a
// credential-loading failure. The SDK error alone ("failed to refresh cached
// credentials") does not tell an operator which of the four sources was
// expected, which is the actual cause of most first-run failures.
func EntryCredentialHint(profile string) string {
	return fmt.Sprintf("no usable entry credential from %s; see docs/aws-credential-setup.md §2",
		EntryCredentialSource(profile))
}
