package handler

import (
	"app/database"
	"app/model"
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// Hello handle api status
func Hello(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "success", "message": "Hello i'm ok!", "data": nil})
}

func ProtectedEndpointTest(c *fiber.Ctx) error {
	// Extract the token from context
	token := c.Locals("user").(*jwt.Token)

	// Extract the claims from the token
	claims := token.Claims.(jwt.MapClaims)

	// Retrieve the user_id from the claims
	id := claims["user_id"].(float64) // JWT claims store numbers as float64

	// Convert user_id from float64 to uint if your user model uses uint
	userID := uint(id)

	// Now use the userID to query the database
	db := database.DB
	var user model.User

	// Fetch the user by ID
	if err := db.First(&user, userID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"status": "error", "message": "User not found", "data": nil})
	}

	// Return the user information
	return c.JSON(fiber.Map{"status": "success", "message": "id: " + fmt.Sprint(userID) + "; " + user.Username, "data": nil})
}
