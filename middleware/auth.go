package middleware

import (
	"app/config"
	"context"
	"encoding/json"
	"fmt"
	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"
	"time"
)

// Protected protect routes
func Protected() fiber.Handler {
	return jwtware.New(jwtware.Config{
		SigningKey:   jwtware.SigningKey{Key: []byte(config.Config("SECRET"))},
		ErrorHandler: jwtError,
	})
}

func jwtError(c *fiber.Ctx, err error) error {
	if err.Error() == "Missing or malformed JWT" {
		return c.Status(fiber.StatusBadRequest).
			JSON(fiber.Map{"status": "error", "message": "Missing or malformed JWT", "data": nil})
	}
	return c.Status(fiber.StatusUnauthorized).
		JSON(fiber.Map{"status": "error", "message": "Invalid or expired JWT", "data": nil})
}

func SendCookie(c *fiber.Ctx, accessToken, refreshToken string) error {
	// Set the access token in a cookie
	accessCookie := new(fiber.Cookie)
	accessCookie.Name = "access_token"
	accessCookie.Value = accessToken
	accessCookie.Expires = time.Now().Add(72 * time.Hour)
	accessCookie.HTTPOnly = true
	accessCookie.Secure = false
	accessCookie.SameSite = "Lax"

	// Set the refresh token in a cookie
	refreshCookie := new(fiber.Cookie)
	refreshCookie.Name = "refresh_token"
	refreshCookie.Value = refreshToken
	refreshCookie.Expires = time.Now().Add(168 * time.Hour)
	refreshCookie.HTTPOnly = true // Prevents access from JavaScript
	refreshCookie.Secure = false  // Ensure the cookie is sent only over HTTPS
	refreshCookie.SameSite = "Lax"
	fmt.Println("Refresh Token:", refreshToken)

	// Send the cookies to the client
	c.Cookie(accessCookie)
	c.Cookie(refreshCookie)

	return c.JSON(fiber.Map{"status": "success", "message": "Success login"})
}

func getTokensFromCookie(c *fiber.Ctx) (string, string, error) {

	accessToken := c.Cookies("access_token")
	if accessToken == "" {
		return "", "", fmt.Errorf("access token cookie not found")
	}

	refreshToken := c.Cookies("refresh_token")
	if refreshToken == "" {
		return "", "", fmt.Errorf("refresh token cookie not found")
	}

	return accessToken, refreshToken, nil
}

func FetchUserData(c *fiber.Ctx, googleOauthConfig *oauth2.Config) error {
	c.Locals("status", "success")

	// Extract tokens from cookies
	accessToken, refreshToken, err := getTokensFromCookie(c)
	if err != nil {
		c.Locals("status", "error")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "error", "message": "Unauthorized"})
	}

	access_token := &oauth2.Token{
		AccessToken: accessToken,
		Expiry:      time.Now().Add(24 * time.Hour),
	}

	refresh_token := &oauth2.Token{
		AccessToken: refreshToken,
		Expiry:      time.Now().Add(168 * time.Hour),
	}
	fmt.Println("access_token Expiry Time:", access_token.Expiry)
	if isTokenExpired(access_token) {
		fmt.Println("Access token has expired.")
		if isTokenExpired(refresh_token) {
			fmt.Println("Refresh token has expired.")
			new_access_token, err := refreshAccessToken(googleOauthConfig, refresh_token)
			if err != nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "error", "message": "Failed to refresh token"})
			}
			c.Cookie(&fiber.Cookie{
				Name:  "access_token",
				Value: new_access_token.AccessToken,
			})

			c.Cookie(&fiber.Cookie{
				Name:  "refresh_token",
				Value: new_access_token.RefreshToken,
			})

			accessToken = new_access_token.AccessToken
		}
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "error", "message": "Access/Refresh token have expired"})
	}
	// Use the access token to create the OAuth client
	client := googleOauthConfig.Client(context.Background(), &oauth2.Token{AccessToken: accessToken})
	resp, err := client.Get("https://www.googleapis.com/userinfo/v2/me")
	if err != nil {
		c.Locals("status", "error")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Error fetching user data"})
	}
	defer resp.Body.Close()

	// Decode the user info from the response
	var userData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		c.Locals("status", "error")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Error decoding response"})
	}

	// Return user data
	return c.JSON(fiber.Map{"status": "success", "data": userData})
}

func isTokenExpired(token *oauth2.Token) bool {
	return token.Expiry.Before(time.Now())
}

func refreshAccessToken(googleOauthConfig *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) {

	tokenSource := googleOauthConfig.TokenSource(context.Background(), token)

	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("unable to refresh token: %v", err)
	}

	return newToken, nil
}
