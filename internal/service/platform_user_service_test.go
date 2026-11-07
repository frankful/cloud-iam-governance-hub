package service

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakePlatformUserRepository struct {
	users      map[string]PlatformUser
	upserts    []UpsertPlatformUser
	upsertErr  error
	findErr    error
	upsertCall int
}

func newFakePlatformUserRepository() *fakePlatformUserRepository {
	return &fakePlatformUserRepository{users: map[string]PlatformUser{}}
}

func (repository *fakePlatformUserRepository) ListUsers(context.Context) ([]PlatformUser, error) {
	users := make([]PlatformUser, 0, len(repository.users))
	for _, user := range repository.users {
		users = append(users, user)
	}
	return users, nil
}

func (repository *fakePlatformUserRepository) FindUser(
	_ context.Context,
	userID string,
) (PlatformUser, error) {
	if repository.findErr != nil {
		return PlatformUser{}, repository.findErr
	}
	user, exists := repository.users[userID]
	if !exists {
		return PlatformUser{}, ErrPlatformUserNotFound
	}
	return user, nil
}

func (repository *fakePlatformUserRepository) UpsertUser(
	_ context.Context,
	user UpsertPlatformUser,
	actorID string,
) error {
	repository.upsertCall++
	if repository.upsertErr != nil {
		return repository.upsertErr
	}
	repository.upserts = append(repository.upserts, user)
	active := true
	if user.IsActive != nil {
		active = *user.IsActive
	}
	repository.users[user.UserID] = PlatformUser{
		UserID: user.UserID, DisplayName: user.DisplayName,
		Roles: user.Roles, IsActive: active,
	}
	return nil
}

func newTestPlatformUserService(
	t *testing.T,
	repository *fakePlatformUserRepository,
) *PlatformUserService {
	t.Helper()
	tokenService, err := NewPlatformTokenService(&fakePlatformTokenRepository{
		userExists: true, userRoles: []string{"platform_admin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	userService, err := NewPlatformUserService(repository, tokenService)
	if err != nil {
		t.Fatal(err)
	}
	return userService
}

func boolPointer(value bool) *bool { return &value }

func TestUpsertPlatformUserRejectsInvalidInputBeforePersistence(t *testing.T) {
	repository := newFakePlatformUserRepository()
	service := newTestPlatformUserService(t, repository)

	for _, test := range []struct {
		name string
		user UpsertPlatformUser
	}{
		{
			name: "missing user id",
			user: UpsertPlatformUser{DisplayName: "Alice", Roles: []string{"standard_user"}},
		},
		{
			name: "missing display name",
			user: UpsertPlatformUser{UserID: "alice", Roles: []string{"standard_user"}},
		},
		{
			name: "invalid e-mail",
			user: UpsertPlatformUser{
				UserID: "alice", DisplayName: "Alice",
				Email: "not-an-address", Roles: []string{"standard_user"},
			},
		},
		{
			name: "unknown role",
			user: UpsertPlatformUser{
				UserID: "alice", DisplayName: "Alice", Roles: []string{"superuser"},
			},
		},
		{
			name: "no role",
			user: UpsertPlatformUser{UserID: "alice", DisplayName: "Alice"},
		},
	} {
		if err := service.UpsertUser(context.Background(), test.user, "admin"); err == nil {
			t.Errorf("%s: expected validation error", test.name)
		}
	}
	if repository.upsertCall != 0 {
		t.Fatalf("repository was called %d times for invalid input", repository.upsertCall)
	}
}

func TestUpsertPlatformUserNormalizesRolesAndReplacesThem(t *testing.T) {
	repository := newFakePlatformUserRepository()
	service := newTestPlatformUserService(t, repository)

	err := service.UpsertUser(context.Background(), UpsertPlatformUser{
		UserID:      " alice ",
		DisplayName: " Alice ",
		Email:       " alice@example.com ",
		Roles:       []string{" standard_user ", "standard_user", "approval_admin"},
	}, "admin")
	if err != nil {
		t.Fatalf("UpsertUser() error = %v", err)
	}
	if repository.upsertCall != 1 {
		t.Fatalf("repository calls = %d, want 1", repository.upsertCall)
	}
	stored := repository.upserts[0]
	if stored.UserID != "alice" || stored.DisplayName != "Alice" || stored.Email != "alice@example.com" {
		t.Fatalf("stored user = %+v, want trimmed values", stored)
	}
	if len(stored.Roles) != 2 || stored.Roles[0] != "standard_user" || stored.Roles[1] != "approval_admin" {
		t.Fatalf("stored roles = %v, want deduplicated roles", stored.Roles)
	}
	if stored.IsActive == nil || !*stored.IsActive {
		t.Fatal("a new user must be active by default")
	}
}

// 停用用户不能被一次局部更新悄悄启用回来。
func TestUpsertPlatformUserKeepsActiveFlagWhenNotProvided(t *testing.T) {
	repository := newFakePlatformUserRepository()
	repository.users["alice"] = PlatformUser{
		UserID: "alice", DisplayName: "Alice", IsActive: false,
		Roles: []string{"standard_user"},
	}
	service := newTestPlatformUserService(t, repository)

	if err := service.UpsertUser(context.Background(), UpsertPlatformUser{
		UserID: "alice", DisplayName: "Alice Renamed", Roles: []string{"standard_user"},
	}, "admin"); err != nil {
		t.Fatalf("UpsertUser() error = %v", err)
	}
	stored := repository.upserts[0]
	if stored.IsActive == nil || *stored.IsActive {
		t.Fatal("an omitted is_active must keep the stored value (a deactivated user stays deactivated)")
	}
}

// 管理员不能把自己锁在门外。
func TestUpsertPlatformUserRejectsSelfLockout(t *testing.T) {
	repository := newFakePlatformUserRepository()
	service := newTestPlatformUserService(t, repository)

	err := service.UpsertUser(context.Background(), UpsertPlatformUser{
		UserID: "admin", DisplayName: "Admin",
		IsActive: boolPointer(false), Roles: []string{"platform_admin"},
	}, "admin")
	if err == nil {
		t.Fatal("deactivating your own account must be rejected")
	}

	err = service.UpsertUser(context.Background(), UpsertPlatformUser{
		UserID: "admin", DisplayName: "Admin",
		Roles: []string{"standard_user"},
	}, "admin")
	if err == nil {
		t.Fatal("removing your own platform_admin role must be rejected")
	}
	if repository.upsertCall != 0 {
		t.Fatalf("repository was called %d times for a rejected self-lockout", repository.upsertCall)
	}
}

func TestUpsertPlatformUserRequiresAuthenticatedActor(t *testing.T) {
	repository := newFakePlatformUserRepository()
	service := newTestPlatformUserService(t, repository)

	err := service.UpsertUser(context.Background(), UpsertPlatformUser{
		UserID: "alice", DisplayName: "Alice", Roles: []string{"standard_user"},
	}, "  ")
	if err == nil {
		t.Fatal("an empty actor must be rejected")
	}
}

func TestPlatformUserServiceListsUsersAndIssuesTokens(t *testing.T) {
	repository := newFakePlatformUserRepository()
	repository.users["alice"] = PlatformUser{
		UserID: "alice", DisplayName: "Alice", IsActive: true,
		Roles: []string{"standard_user"},
	}
	tokenRepository := &fakePlatformTokenRepository{
		userExists: true, userRoles: []string{"standard_user"},
	}
	tokenService, err := NewPlatformTokenService(tokenRepository)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewPlatformUserService(repository, tokenService)
	if err != nil {
		t.Fatal(err)
	}

	users, err := service.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("ListUsers() error = %v", err)
	}
	if len(users) != 1 || users[0].UserID != "alice" {
		t.Fatalf("users = %+v", users)
	}

	issued, err := service.IssueToken(context.Background(), "admin", "alice", "console", nil)
	if err != nil {
		t.Fatalf("IssueToken() error = %v", err)
	}
	if issued.UserID != "alice" {
		t.Fatalf("issued token = %+v", issued)
	}
	if tokenRepository.actorID != "admin" {
		t.Fatalf("token actor = %q, want the issuing administrator", tokenRepository.actorID)
	}
}

func TestPlatformUserServicePropagatesRepositoryErrors(t *testing.T) {
	repository := newFakePlatformUserRepository()
	repository.upsertErr = errors.New("database is down")
	service := newTestPlatformUserService(t, repository)

	err := service.UpsertUser(context.Background(), UpsertPlatformUser{
		UserID: "alice", DisplayName: "Alice", Roles: []string{"standard_user"},
	}, "admin")
	if err == nil {
		t.Fatal("expected the repository error to surface")
	}
}

func TestListTokensFiltersByUser(t *testing.T) {
	tokenRepository := &fakePlatformTokenRepository{
		tokens: []PlatformTokenInfo{
			{ID: 1, UserID: "alice", Name: "laptop"},
			{ID: 2, UserID: "bob", Name: "laptop"},
		},
	}
	tokenService, err := NewPlatformTokenService(tokenRepository)
	if err != nil {
		t.Fatal(err)
	}
	repository := newFakePlatformUserRepository()
	service, err := NewPlatformUserService(repository, tokenService)
	if err != nil {
		t.Fatal(err)
	}

	tokens, err := service.ListTokens(context.Background(), "alice")
	if err != nil {
		t.Fatalf("ListTokens() error = %v", err)
	}
	if len(tokens) != 1 || tokens[0].UserID != "alice" {
		t.Fatalf("tokens = %+v, want only alice's token", tokens)
	}
	_ = time.Now
}
