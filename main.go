package main

import (
	"authorization_token_repo"
	"context"
	"encoding/json"
	"github.com/aws/aws-lambda-go/lambda"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
)

type MyEvent struct {
	Provider string `json:"provider"`
}

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int16  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
}


func HandleRequest(ctx context.Context, name MyEvent) (str string, err error) {
	bearer, refresh := authorization_token_repo.Fetch(name.Provider)

	var tokenResp = AccessTokenResponse{}
	var bytes []byte
	if bearer.IsExpired() {
		tokenResp = RefreshToken(refresh)
		bytes, err = json.Marshal(&tokenResp)
		str = string(bytes)
	} else {
		bytes, err = json.Marshal(&AccessTokenResponse{
			AccessToken:  bearer.Token,
			ExpiresIn:    bearer.ExpiresIn,
			TokenType:    bearer.TokenType,
			Scope:        "",
			RefreshToken: refresh.Token,
		})
		str = string(bytes)
	}
	return
}

func RefreshToken(entity authorization_token_repo.TokenEntity) (accessToken AccessTokenResponse) {
	apiUrl := "https://cloud.lightspeedapp.com"
	resource := "/oauth/access_token.php"
	data := url.Values{}
	data.Set("refresh_token", entity.Token)
	data.Set("client_id", os.Getenv("lightspeed_client_id"))
	data.Set("client_secret", os.Getenv("lightspeed_client_secret"))
	data.Set("grant_type", "refresh_token")

	u, _ := url.ParseRequestURI(apiUrl)
	u.Path = resource
	urlStr := u.String() // "https://api.com/user/"

	log.Print(urlStr)

	client := &http.Client{}
	r, _ := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode())) // URL-encoded payload
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))

	if resp, err := client.Do(r); err != nil {
		log.Print(err)
	} else {
		body, _ := ioutil.ReadAll(resp.Body)
		json.Unmarshal([]byte(body), &accessToken)
		authorization_token_repo.SaveBearer(
			accessToken.AccessToken,
			accessToken.ExpiresIn,
		)

		authorization_token_repo.SaveRefresh(
			accessToken.RefreshToken,
			accessToken.ExpiresIn,
		)
	}

	return accessToken
}

func main() {
	lambda.Start(HandleRequest)
}