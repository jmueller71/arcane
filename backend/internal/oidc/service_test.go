package oidc

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/libtnb/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/getarcaneapp/arcane/backend/v2/internal/auth"
	"github.com/getarcaneapp/arcane/backend/v2/internal/config"
	"github.com/getarcaneapp/arcane/backend/v2/internal/database"
	"github.com/getarcaneapp/arcane/backend/v2/internal/settings"
)

func TestValidateMobileRedirectURI(t *testing.T) {
	ctx := t.Context()
	s := &OidcService{
		config: &config.Config{
			OidcMobileRedirectUris: "arcane-mobile://oidc-callback, arcane-mobile://oauth",
		},
	}

	cases := []struct {
		name    string
		uri     string
		wantErr bool
	}{
		{"exact match first", "arcane-mobile://oidc-callback", false},
		{"exact match second", "arcane-mobile://oauth", false},
		{"empty rejected", "", true},
		{"scheme-only attack", "arcane-mobile://attacker", true},
		{"different scheme", "https://oidc-callback", true},
		{"trailing-slash mismatch", "arcane-mobile://oidc-callback/", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := s.ValidateMobileRedirectURI(ctx, tc.uri)

			require.Equal(t, tc.wantErr, err != nil,
				"ValidateMobileRedirectURI(%q): wantErr=%v got err=%v", tc.uri, tc.wantErr, err)
		})
	}
}

func TestGetMobileRedirectAllowlistTrimsWhitespace(t *testing.T) {
	ctx := t.Context()
	s := &OidcService{
		config: &config.Config{
			OidcMobileRedirectUris: "  arcane-mobile://a  ,arcane-mobile://b ,, arcane-mobile://c",
		},
	}

	got := s.GetMobileRedirectAllowlist(ctx)
	want := []string{"arcane-mobile://a", "arcane-mobile://b", "arcane-mobile://c"}
	if len(got) != len(want) {
		require.Len(t, got, len(want),
			"got %d entries (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i, w := range want {
		require.Equal(t, w, got[i],
			"entry %d: got %q, want %q", i, got[i], w)
	}
}

func TestGetMobileRedirectAllowlistUsesSettings(t *testing.T) {
	ctx := t.Context()
	db := setupSettingsTestDB(t)
	settingsService, err := newSettingsServiceForTest(t, ctx, db)

	require.NoError(t, err,
		"settings.NewSettingsService: %v", err)
	{

		updateSettingErr := settingsService.UpdateSetting(ctx, "oidcMobileRedirectUris", "arcane-mobile://db-callback")
		require.NoError(t, updateSettingErr,
			"UpdateSetting: %v", updateSettingErr)
	}

	s := &OidcService{
		settingsService: settingsService,
		config: &config.Config{
			OidcMobileRedirectUris: "arcane-mobile://config-callback",
		},
	}
	{

		validateMobileRedirectURIErr := s.ValidateMobileRedirectURI(ctx, "arcane-mobile://db-callback")
		require.NoError(t, validateMobileRedirectURIErr,
			"ValidateMobileRedirectURI db value: %v", validateMobileRedirectURIErr)
	}
	{

		validateMobileRedirectURIErr2 := s.ValidateMobileRedirectURI(ctx, "arcane-mobile://config-callback")
		require.Error(t, validateMobileRedirectURIErr2,
			"ValidateMobileRedirectURI config fallback should fail when DB setting is configured")
	}
}

func TestGetProviderLogoutURL(t *testing.T) {
	endSessionEndpoint := ""
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		metadata := map[string]any{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
			"jwks_uri":               server.URL + "/jwks",
		}
		if endSessionEndpoint != "" {
			metadata["end_session_endpoint"] = endSessionEndpoint
		}
		assert.NoError(t, json.MarshalWrite(w, metadata))
	}))
	t.Cleanup(server.Close)

	newService := func(t *testing.T, overrides map[string]string) *OidcService {
		t.Helper()
		ctx := t.Context()
		settingsService, err := newSettingsServiceForTest(t, ctx, setupSettingsTestDB(t))
		require.NoError(t, err)
		values := map[string]string{
			"oidcEnabled":        "true",
			"oidcClientId":       "arcane-client",
			"oidcIssuerUrl":      server.URL,
			"oidcProviderLogout": "true",
		}
		for key, value := range overrides {
			values[key] = value
		}
		for key, value := range values {
			require.NoError(t, settingsService.UpdateSetting(ctx, key, value))
		}
		cfg := &config.Config{}
		authService := auth.NewAuthService(nil, settingsService, nil, nil, nil, cfg)
		return NewOidcService(authService, settingsService, cfg, server.Client(), nil)
	}

	t.Run("uses discovered end session endpoint", func(t *testing.T) {
		endSessionEndpoint = server.URL + "/end-session/"
		t.Cleanup(func() { endSessionEndpoint = "" })

		got, err := newService(t, nil).GetProviderLogoutURL(t.Context(), "https://arcane.example")
		require.NoError(t, err)

		parsed, err := url.Parse(got)
		require.NoError(t, err)
		require.Equal(t, server.URL+"/end-session/", parsed.Scheme+"://"+parsed.Host+parsed.Path)
		require.Equal(t, "arcane-client", parsed.Query().Get("client_id"))
		require.Equal(t, "https://arcane.example/logged-out", parsed.Query().Get("post_logout_redirect_uri"))
		require.Empty(t, parsed.Query().Get("id_token_hint"))
	})

	t.Run("manual endpoint takes precedence and keeps its query", func(t *testing.T) {
		endSessionEndpoint = server.URL + "/end-session/"
		t.Cleanup(func() { endSessionEndpoint = "" })

		got, err := newService(t, map[string]string{
			"oidcEndSessionEndpoint": "https://idp.example/logout?tenant=main",
		}).GetProviderLogoutURL(t.Context(), "https://arcane.example")
		require.NoError(t, err)

		parsed, err := url.Parse(got)
		require.NoError(t, err)
		require.Equal(t, "idp.example", parsed.Host)
		require.Equal(t, "/logout", parsed.Path)
		require.Equal(t, "main", parsed.Query().Get("tenant"))
		require.Equal(t, "arcane-client", parsed.Query().Get("client_id"))
		require.Equal(t, "https://arcane.example/logged-out", parsed.Query().Get("post_logout_redirect_uri"))
	})

	t.Run("returns empty URL when provider logout is disabled", func(t *testing.T) {
		got, err := newService(t, map[string]string{"oidcProviderLogout": "false"}).GetProviderLogoutURL(t.Context(), "https://arcane.example")
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("returns empty URL when OIDC is disabled", func(t *testing.T) {
		got, err := newService(t, map[string]string{"oidcEnabled": "false"}).GetProviderLogoutURL(t.Context(), "https://arcane.example")
		require.NoError(t, err)
		require.Empty(t, got)
	})

	t.Run("fails when provider does not advertise an end session endpoint", func(t *testing.T) {
		got, err := newService(t, nil).GetProviderLogoutURL(t.Context(), "https://arcane.example")
		require.Error(t, err)
		require.Empty(t, got)
	})
}

// Test fixtures shared by this package's tests.

func setupSettingsTestDB(t *testing.T) *database.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&settings.SettingVariable{}))
	return &database.DB{DB: db}
}

func newSettingsServiceForTest(t testing.TB, ctx context.Context, db *database.DB) (*settings.SettingsService, error) {
	t.Helper()
	svc, err := settings.NewSettingsService(ctx, db, &config.Config{})
	if err == nil {
		t.Cleanup(func() { require.NoError(t, svc.Stop(context.WithoutCancel(t.Context()))) })
	}
	return svc, err
}
