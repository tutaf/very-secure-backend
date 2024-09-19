package middleware

import (
	"app/config"
	"context"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
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
	// Create JWT token
	token := jwt.New(jwt.SigningMethodHS256)

	// Add access token and refresh token to JWT claims
	claims := token.Claims.(jwt.MapClaims)
	claims["access_token"] = accessToken
	claims["refresh_token"] = refreshToken
	claims["exp"] = time.Now().Add(time.Hour * 72).Unix() // Set expiration time for JWT (72 hours)

	// Sign the JWT token with a secret
	jwtToken, err := token.SignedString([]byte(config.Config("SECRET")))
	if err != nil {
		return c.SendStatus(fiber.StatusInternalServerError)
	}

	// Set the JWT token in a cookie
	cookie := new(fiber.Cookie)
	cookie.Name = "google_auth_jwt"
	cookie.Value = jwtToken
	cookie.Expires = time.Now().Add(72 * time.Hour) // Set expiration time for the cookie (72 hours)
	cookie.HTTPOnly = true                          // Prevents access from JavaScript
	cookie.Secure = false                           // Ensure the cookie is sent only over HTTPS
	cookie.SameSite = "Lax"

	// Send the cookie to the client
	c.Cookie(cookie)

	return c.JSON(fiber.Map{"status": "success", "message": "Success login"})
}

type JwtClaims struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Exp          int64  `json:"exp"`
	IssuedAt     int64  `json:"iat"`
	Issuer       string `json:"iss"`
	Subject      string `json:"sub"`
}

func (c *JwtClaims) Valid() error {
	now := time.Now().Unix()
	if c.Exp < now {
		return fmt.Errorf("token has expired")
	}
	if c.IssuedAt > now {
		return fmt.Errorf("token is not yet valid")
	}
	return nil
}

func extractAccessTokenFromJWT(jwtToken string, secretKey string) (string, error) {
	claims := &JwtClaims{}
	token, err := jwt.ParseWithClaims(jwtToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil || !token.Valid {
		return "", fmt.Errorf("invalid token")
	}
	return claims.AccessToken, nil
}

func getTokenFromCookie(c *fiber.Ctx) (string, error) {
	jwtToken := c.Cookies("google_auth_jwt")
	if jwtToken == "" {
		return "", fmt.Errorf("cookie not found")
	}
	accessToken, err := extractAccessTokenFromJWT(jwtToken, config.Config("SECRET"))
	if err != nil {
		return "", err
	}
	return accessToken, nil
}

func FetchUserData(c *fiber.Ctx, googleOauthConfig *oauth2.Config) error {
	c.Locals("status", "success")

	token, err := getTokenFromCookie(c)
	if err != nil {
		c.Locals("status", "error")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "error", "message": "Unauthorized"})
	}
	client := googleOauthConfig.Client(context.Background(), &oauth2.Token{AccessToken: token})
	resp, err := client.Get("https://www.googleapis.com/userinfo/v2/me")
	if err != nil {
		c.Locals("status", "error")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Error fetching user data"})
	}
	defer resp.Body.Close()

	var userData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		c.Locals("status", "error")
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Error decoding response"})
	}

	return c.JSON(fiber.Map{"status": "success", "data": userData})
}
