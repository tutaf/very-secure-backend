package handler

import "github.com/gofiber/fiber/v2"

// Hello handle api status
func Hello(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "success", "message": "Hello i'm ok!", "data": nil})
}

func ProtectedEndpointTest(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "success", "message": "You successfully accessed a protected endpoint!", "data": nil})
}
