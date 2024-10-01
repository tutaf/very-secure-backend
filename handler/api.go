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
	return c.JSON(fiber.Map{"status": "success", "message": "Hello!", "data": nil})
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

func GetFiles(c *fiber.Ctx) error {
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

	data := fiber.Map{
		"items": []fiber.Map{
			{
				"id":   "1",
				"name": "Documents",
				"children": []fiber.Map{
					{
						"id":   "1-1",
						"name": user.Username + "'s Reports",
						"children": []fiber.Map{
							{
								"id":   "1-1-1",
								"name": "2023_Q1_Report.pdf",
								"type": "file",
							},
							{
								"id":   "1-1-2",
								"name": "2023_Q2_Report.pdf",
								"type": "file",
							},
						},
					},
					{
						"id":   "1-2",
						"name": "Invoices",
						"children": []fiber.Map{
							{
								"id":   "1-2-1",
								"name": "Invoice_001.pdf",
								"type": "file",
							},
							{
								"id":   "1-2-2",
								"name": "Invoice_002.pdf",
								"type": "file",
							},
						},
					},
				},
			},
			{
				"id":   "2",
				"name": "Photos",
				"children": []fiber.Map{
					{
						"id":   "2-1",
						"name": "Vacations",
						"children": []fiber.Map{
							{
								"id":   "2-1-1",
								"name": "Beach.jpg",
								"type": "file",
							},
							{
								"id":   "2-1-2",
								"name": "Mountain.jpg",
								"type": "file",
							},
						},
					},
					{
						"id":   "2-2",
						"name": "Family",
						"children": []fiber.Map{
							{
								"id":   "2-2-1",
								"name": "Birthday.jpg",
								"type": "file",
							},
						},
					},
				},
			},
			{
				"id":   "3",
				"name": "Music",
				"children": []fiber.Map{
					{
						"id":   "3-1",
						"name": "Pop",
						"children": []fiber.Map{
							{
								"id":   "3-1-1",
								"name": "Hit_Song.mp3",
								"type": "file",
							},
						},
					},
					{
						"id":   "3-2",
						"name": "Classical",
						"children": []fiber.Map{
							{
								"id":   "3-2-1",
								"name": "Symphony_No_5.mp3",
								"type": "file",
							},
						},
					},
				},
			},
		},
	}

	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "Files successfully",
		"data":    data,
	})

}
