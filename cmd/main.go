package main

import (
	"app/database"
	"app/router"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html/v2"
)

func main() {
	engine := html.New("./templates", ".html")

	app := fiber.New(fiber.Config{
		Prefork:       true,
		CaseSensitive: true,
		StrictRouting: true,
		ServerHeader:  "Fiber",
		AppName:       "App Name",
		Views:         engine,
	})

	database.ConnectDB()

	router.SetupRoutes(app)

	log.Fatal(app.Listen(":3000"))
}
