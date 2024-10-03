package handler

import (
	"app/database"
	"app/model"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
	"golang.org/x/crypto/bcrypt"
	"strconv"
	"time"
)

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func validToken(t *jwt.Token, id string) bool {
	n, err := strconv.Atoi(id)
	if err != nil {
		return false
	}

	claims := t.Claims.(jwt.MapClaims)
	uid := int(claims["user_id"].(float64))

	return uid == n
}

func validUser(id string, p string) bool {
	db := database.DB
	var user model.User
	db.First(&user, id)
	if user.Username == "" {
		return false
	}
	if !CheckPasswordHash(p, user.Password) {
		return false
	}
	return true
}

// GetUser get a user
func GetUser(c *fiber.Ctx) error {
	id := c.Params("id")
	db := database.DB
	var user model.User
	db.Find(&user, id)
	if user.Username == "" {
		return c.Status(404).JSON(fiber.Map{"status": "error", "message": "No user found with ID", "data": nil})
	}
	return c.JSON(fiber.Map{"status": "success", "message": "User found", "data": user})
}

// CreateUser new user
func CreateUser(c *fiber.Ctx) error {
	type NewUser struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Secret   string `json:"secret"`
		QRCode   string `json:"qr_code"` // New field for QR code URL
	}

	db := database.DB
	user := new(model.User)
	if err := c.BodyParser(user); err != nil {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Review your input", "errors": err.Error()})
	}

	// Generate a random secret key with a length of 16 characters
	user.Secret = gotp.RandomSecret(16)

	validate := validator.New()
	if err := validate.Struct(user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"message": "Invalid request body", "errors": err.Error()})
	}

	hash, err := hashPassword(user.Password)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Couldn't hash password", "errors": err.Error()})
	}

	user.Password = hash
	if err := db.Create(&user).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Couldn't create user", "errors": err.Error()})
	}

	// Generate a provisioning URI for the TOTP, used for QR code generation
	uri := gotp.NewDefaultTOTP(user.Secret).ProvisioningUri(user.Email, "MyApp")

	// Generate a QR code image for the provisioning URI and save it to a specific path
	qrCodePath := "public/qr_codes/" + user.Username + "_qr.png" // Example path for QR code
	err = qrcode.WriteFile(uri, qrcode.Medium, 256, qrCodePath)  // Using the function as you suggested
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Couldn't generate QR code", "errors": err.Error()})
	}

	// Build the public URL to return to the client
	qrCodeURL := "/qr_codes/" + user.Username + "_qr.png"

	newUser := NewUser{
		Email:    user.Email,
		Username: user.Username,
		Secret:   user.Secret,
		QRCode:   qrCodeURL, // Add the QR code URL
	}

	return c.JSON(fiber.Map{"status": "success", "message": "Created user", "data": newUser})
}

func UpdateUser(c *fiber.Ctx) error {
	type UpdateUserInput struct {
		Names     string `json:"names"`
		TwoFACode string `json:"two_fa_code"` // New field for TOTP code
	}

	var uui UpdateUserInput
	if err := c.BodyParser(&uui); err != nil {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Review your input", "errors": err.Error()})
	}

	id := c.Params("id")
	token := c.Locals("user").(*jwt.Token)

	if !validToken(token, id) {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Invalid token id", "data": nil})
	}

	db := database.DB
	var user model.User

	if err := db.First(&user, id).Error; err != nil {
		return c.Status(404).JSON(fiber.Map{"status": "error", "message": "User not found"})
	}

	// Verify the provided TOTP code
	totp := gotp.NewDefaultTOTP(user.Secret) // Get the stored secret for TOTP
	if !totp.Verify(uui.TwoFACode, time.Now().Unix()) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "error", "message": "Invalid 2FA code"})
	}

	// Proceed with the update
	user.Names = uui.Names
	if err := db.Save(&user).Error; err != nil {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Couldn't update user", "errors": err.Error()})
	}

	return c.JSON(fiber.Map{"status": "success", "message": "User successfully updated", "data": user})
}

// DeleteUser delete user
func DeleteUser(c *fiber.Ctx) error {
	type PasswordInput struct {
		Password string `json:"password"`
	}
	var pi PasswordInput
	if err := c.BodyParser(&pi); err != nil {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Review your input", "errors": err.Error()})
	}
	id := c.Params("id")
	token := c.Locals("user").(*jwt.Token)

	if !validToken(token, id) {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Invalid token id", "data": nil})

	}

	if !validUser(id, pi.Password) {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Not valid user", "data": nil})

	}

	db := database.DB
	var user model.User

	db.First(&user, id)

	db.Delete(&user)
	return c.JSON(fiber.Map{"status": "success", "message": "User successfully deleted", "data": nil})
}
