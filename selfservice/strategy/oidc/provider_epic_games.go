// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/ory/x/httpx"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/ory/herodot"
)

type ProviderEpicGames struct {
	config *Configuration
	reg    Dependencies
}

type EpicGamesIdentityResponse struct {
	Data struct {
		Attributes struct {
			Email     string `json:"email"`
			FirstName string `json:"first_name"`
			FullName  string `json:"full_name"`
			ImageUrl  string `json:"image_url"`
			LastName  string `json:"last_name"`
		} `json:"attributes"`
		Id   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
}

func NewProviderEpicGames(
	config *Configuration,
	reg Dependencies,
) Provider {
	return &ProviderEpicGames{
		config: config,
		reg:    reg,
	}
}

func (d *ProviderEpicGames) Config() *Configuration {
	return d.config
}

func (d *ProviderEpicGames) oauth2(ctx context.Context) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     d.config.ClientID,
		ClientSecret: d.config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://www.epicgames.com/id/authorize",
			TokenURL:  "https://api.epicgames.dev/epic/oauth/v1/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: d.config.Redir(d.reg.Config().OIDCRedirectURIBase(ctx)),
		Scopes:      d.config.Scope,
	}
}

func (d *ProviderEpicGames) OAuth2(ctx context.Context) (*oauth2.Config, error) {
	d.reg.Logger().WithField("provider", "epic-games").Trace("ProviderCreating new oauth2 configuration in OAuth2 method.")
	return d.oauth2(ctx), nil
}

func (d *ProviderEpicGames) Claims(ctx context.Context, exchange *oauth2.Token, query url.Values) (*Claims, error) {
	identityUrl := "https://api.epicgames.dev/epic/oauth/v1/userInfo"

	o := d.oauth2(ctx)
	client := d.reg.HTTPClient(ctx, httpx.ResilientClientWithClient(o.Client(ctx, exchange)))

	req, err := retryablehttp.NewRequest("GET", identityUrl, nil)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+exchange.AccessToken)

	res, err := client.Do(req)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", err))
	}
	defer res.Body.Close()

	if err := logUpstreamError(d.reg.Logger(), res); err != nil {
		return nil, err
	}

	data := EpicGamesIdentityResponse{}
	jsonErr := json.NewDecoder(res.Body).Decode(&data)
	if jsonErr != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("%s", jsonErr))
	}

	claims := &Claims{
		Issuer:     "https://api.epicgames.dev/epic/oauth/v1",
		Subject:    data.Data.Id,
		Name:       data.Data.Attributes.FullName,
		Email:      data.Data.Attributes.Email,
		GivenName:  data.Data.Attributes.FirstName,
		FamilyName: data.Data.Attributes.LastName,
		LastName:   data.Data.Attributes.LastName,
		Picture:    data.Data.Attributes.ImageUrl,
	}

	return claims, nil
}

func (g *ProviderEpicGames) AuthCodeURLOptions(r ider) []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{}
}
