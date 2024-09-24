package middleware

import (
	"app/config"
	"app/database"
	"app/model"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
	"log"
	"strconv"
	"time"

	jwtware "github.com/gofiber/contrib/jwt"
	"github.com/gofiber/fiber/v2"
)

// Protected protect routes
func Protected() fiber.Handler {
	return jwtware.New(jwtware.Config{
		SigningKey:   jwtware.SigningKey{Key: []byte(config.Config("SECRET"))},
		ErrorHandler: jwtError,
		TokenLookup:  "cookie:access_token",
	})
}

// jwtError handles JWT validation errors
func jwtError(c *fiber.Ctx, err error) error {
	// Check if refresh token is valid
	refreshToken := c.Cookies("refresh_token")
	if refreshToken == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"status":  "error",
			"message": "Missing a valid JWT and/or refresh token",
			"data":    nil,
		})
	}

	// validate the refresh token from the database
	refreshTokenRecord, err := ValidateRefreshToken(database.DB, refreshToken)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "error", "message": "Error while refreshing tokens: Invalid refresh token", "error": err.Error()})
	}

	// get the user associated with the refresh token
	user, err := getUserByID(refreshTokenRecord.UserID)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "error", "message": "Error while refreshing tokens: Failed to retrieve user", "error": err.Error()})
	}

	// generate new JWT access token
	newAccessToken, err := generateJWT(*user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Error while refreshing tokens: Failed to generate new access token", "error": err.Error()})
	}

	// generate new refresh token
	newRefreshToken, err := GenerateRefreshToken(database.DB, *user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Error while refreshing tokens: Failed to generate new refresh token", "error": err.Error()})
	}

	// invalidate old refresh token by deleting it
	if err := deleteRefreshToken(database.DB, refreshTokenRecord.Token); err != nil {
		log.Println("Warning: Failed to invalidate old refresh token")
	}

	accessTokenLifetime, err := strconv.Atoi(config.Config("ACCESS_TOKEN_LIFETIME_SECONDS"))
	if err != nil {
		return fmt.Errorf("failed to parse access token lifetime: %v", err)
	}

	refreshTokenLifetime, err := strconv.Atoi(config.Config("REFRESH_TOKEN_LIFETIME_HOURS"))
	if err != nil {
		return fmt.Errorf("failed to parse refresh token lifetime: %v", err)
	}

	// set access and refresh tokens as an HTTP-only cookies
	c.Cookie(&fiber.Cookie{
		Name:     "access_token",                                                   // Cookie name for access token
		Value:    newAccessToken,                                                   // The generated access token
		Expires:  time.Now().Add(time.Duration(accessTokenLifetime) * time.Second), // Set expiry for access token
		HTTPOnly: true,                                                             // Ensure it's not accessible via JavaScript
		Secure:   false,                                                            // Should be true if using HTTPS
		SameSite: "Lax",                                                            // Helps prevent CSRF attacks
	})

	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",                                                 // Cookie name for refresh token
		Value:    newRefreshToken,                                                 // The generated refresh token
		Expires:  time.Now().Add(time.Duration(refreshTokenLifetime) * time.Hour), // Set expiry for refresh token
		HTTPOnly: true,                                                            // Ensure it's not accessible via JavaScript
		Secure:   false,                                                           // Should be true if using HTTPS
		SameSite: "Lax",                                                           // Helps prevent CSRF attacks
	})

	// parse the new JWT access token so that it can be stored as a *jwt.Token
	parsedToken, err := jwt.Parse(newAccessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.Config("SECRET")), nil
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Failed to parse newly generated access token", "error": err.Error()})
	}

	// Set the newly parsed token in Locals so it can be used in the rest of the request
	c.Locals("user", parsedToken)

	log.Println("tokens were refreshed")

	// continue to the next middleware or handler
	return c.Next()
}

// helper function to generate JWT
func generateJWT(user model.User) (string, error) {
	// convert the token lifetime from string to integer
	accessTokenLifetime, err := strconv.Atoi(config.Config("ACCESS_TOKEN_LIFETIME_SECONDS"))
	if err != nil {
		return "", fmt.Errorf("failed to parse access token lifetime: %v", err)
	}

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = user.Username
	claims["user_id"] = user.ID

	claims["exp"] = time.Now().Add(time.Duration(accessTokenLifetime) * time.Second).Unix()

	secret := []byte(config.Config("SECRET"))
	return token.SignedString(secret)
}

// helper function to delete/invalidate a refresh token
func deleteRefreshToken(db *gorm.DB, token string) error {
	return db.Where("token = ?", token).Delete(&model.RefreshToken{}).Error
}

// helper function to get a user by ID
func getUserByID(userID uint) (*model.User, error) {
	var user model.User
	if err := database.DB.First(&user, userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func GenerateRefreshToken(db *gorm.DB, user model.User) (string, error) {
	tokenBytes := make([]byte, 64)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", err
	}

	refreshTokenLifetime, err := strconv.Atoi(config.Config("REFRESH_TOKEN_LIFETIME_HOURS"))
	if err != nil {
		return "", fmt.Errorf("failed to parse refresh token lifetime: %v", err)
	}

	token := hex.EncodeToString(tokenBytes)
	expiresAt := time.Now().Add(time.Duration(refreshTokenLifetime) * time.Hour)

	refreshToken := model.RefreshToken{
		Token:     token,
		UserID:    user.ID,
		ExpiresAt: expiresAt,
	}

	if err := db.Create(&refreshToken).Error; err != nil {
		return "", err
	}

	return token, nil
}

func ValidateRefreshToken(db *gorm.DB, token string) (*model.RefreshToken, error) {
	var refreshToken model.RefreshToken
	if err := db.Where("token = ? AND expires_at > ?", token, time.Now()).First(&refreshToken).Error; err != nil {
		return nil, err
	}

	return &refreshToken, nil
}

func DeleteExpiredTokens(db *gorm.DB) error {
	return db.Where("expires_at < ?", time.Now()).Delete(&model.RefreshToken{}).Error
}
