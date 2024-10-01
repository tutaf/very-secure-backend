package main

import (
	"app/config"
	"app/database"
	"app/router"
	"log"
	"github.com/gofiber/fiber/v2/middleware/cors"
)

func main() {
	app := fiber.New(fiber.Config{
		Prefork:       true,
		CaseSensitive: true,
		StrictRouting: true,
		ServerHeader:  "Fiber",
		AppName:       "App Name",
		Views:         engine,
	})

	// CORS configuration
	app.Use(cors.New(cors.Config{
		AllowOrigins:     config.Config("FRONTEND_URL"), // Frontend URL
		AllowCredentials: true,                          // Allow credentials (cookies)
		AllowMethods:     "GET,POST,PUT,DELETE,OPTIONS", // Allowed HTTP methods
		AllowHeaders:     "Content-Type, Authorization", // Allowed headers
	}))

	// Connect to the database
	database.ConnectDB()

	// Set up routes
	router.SetupRoutes(app)

	// Start the server on port 3000
	log.Fatal(app.Listen(":3000"))
}
