package handler

import (
	"app/config"
	"app/database"
	"app/model"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"strconv"
	"time"

	"gorm.io/gorm"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

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

// CheckPasswordHash compare password with hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	log.Println(hash, "haaaash")
	return err == nil
}

func getUserByEmail(e string) (*model.User, error) {
	db := database.DB
	var user model.User
	if err := db.Where(&model.User{Email: e}).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func getUserByUsername(u string) (*model.User, error) {
	db := database.DB
	var user model.User
	if err := db.Where(&model.User{Username: u}).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func valid(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// Login get user and password
func Login(c *fiber.Ctx) error {
	type LoginInput struct {
		Identity string `json:"identity"`
		Password string `json:"password"`
	}
	type UserData struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	input := new(LoginInput)
	var ud UserData

	if err := c.BodyParser(input); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "error", "message": "Error on login request", "errors": err.Error()})
	}

	identity := input.Identity
	pass := input.Password
	userModel, err := new(model.User), *new(error)

	if valid(identity) {
		userModel, err = getUserByEmail(identity)
	} else {
		userModel, err = getUserByUsername(identity)
	}

	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Internal Server Error", "data": err})
	} else if userModel == nil {
		CheckPasswordHash(pass, "")
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "error", "message": "Invalid identity or password", "data": err})
	} else {
		ud = UserData{
			ID:       userModel.ID,
			Username: userModel.Username,
			Email:    userModel.Email,
			Password: userModel.Password,
		}
	}

	if !CheckPasswordHash(pass, ud.Password) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "error", "message": "Invalid identity or password", "data": nil})
	}

	// generate JWT access token
	jwtToken, err := generateJWT(*userModel)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Failed to generate JWT", "data": err.Error()})
	}

	// generate refresh token
	refreshToken, err := GenerateRefreshToken(database.DB, *userModel)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Failed to generate refresh token", "data": err.Error()})
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
		Value:    jwtToken,                                                         // The generated access token
		Expires:  time.Now().Add(time.Duration(accessTokenLifetime) * time.Second), // Set expiry for access token
		HTTPOnly: true,                                                             // Ensure it's not accessible via JavaScript
		Secure:   false,                                                            // Should be true if using HTTPS
		SameSite: "Lax",                                                            // Helps prevent CSRF attacks
	})

	c.Cookie(&fiber.Cookie{
		Name:     "refresh_token",                                                 // Cookie name for refresh token
		Value:    refreshToken,                                                    // The generated refresh token
		Expires:  time.Now().Add(time.Duration(refreshTokenLifetime) * time.Hour), // Set expiry for refresh token
		HTTPOnly: true,                                                            // Ensure it's not accessible via JavaScript
		Secure:   false,                                                           // Should be true if using HTTPS
		SameSite: "Lax",                                                           // Helps prevent CSRF attacks
	})

	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "Success login",
	})
}

// Refresh exchanges a valid refresh token for new access and refresh tokens
func Refresh(c *fiber.Ctx) error {
	type refreshRequest struct {
		RefreshToken string `json:"refresh_token"`
	}

	var request refreshRequest
	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "error", "message": "Invalid request", "error": err.Error()})
	}

	// validate the refresh token from the database
	refreshTokenRecord, err := ValidateRefreshToken(database.DB, request.RefreshToken)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "error", "message": "Invalid refresh token", "error": err.Error()})
	}

	// get the user associated with the refresh token
	user, err := getUserByID(refreshTokenRecord.UserID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Failed to retrieve user", "error": err.Error()})
	}

	// generate new JWT access token
	newAccessToken, err := generateJWT(*user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Failed to generate new access token", "error": err.Error()})
	}

	// generate new refresh token
	newRefreshToken, err := GenerateRefreshToken(database.DB, *user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Failed to generate new refresh token", "error": err.Error()})
	}

	// invalidate old refresh token by deleting it
	if err := deleteRefreshToken(database.DB, refreshTokenRecord.Token); err != nil {
		log.Println("Warning: Failed to invalidate old refresh token")
	}

	// Return new tokens to the client
	return c.JSON(fiber.Map{
		"status":        "success",
		"message":       "Tokens refreshed successfully",
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
	})
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
