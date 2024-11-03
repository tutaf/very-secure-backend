package router

import (
	"app/config"
	"app/handler"
	"app/middleware"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var googleOauthConfig = &oauth2.Config{
	RedirectURL:  config.Config("REDIRECT_URL"),
	ClientID:     config.Config("CLIENT_ID"),
	ClientSecret: config.Config("CLIENT_SECRET"),
	Scopes:       []string{"profile", "email"},
	Endpoint:     google.Endpoint,
}

// SetupRoutes setup router api
func SetupRoutes(app *fiber.App) {
	// Middleware
	api := app.Group("/api", logger.New())
	api.Get("/", handler.Hello)
	api.Get("/test/", middleware.Protected(), handler.ProtectedEndpointTest)
	api.Get("/files/", middleware.Protected(), handler.GetFiles)

	// Auth
	auth := api.Group("/auth")
	auth.Get("/google", handler.GoogleAuth)
	auth.Get("/google/callback", handler.GoogleCallback)
	auth.Post("/login", handler.Login)
	auth.Post("/logout", handler.Logout)
	auth.Post("/refresh", handler.Refresh)

	// User
	user := api.Group("/user")
	user.Get("/:id", handler.GetUser)
	user.Post("/", handler.CreateUser)
	user.Patch("/:id", middleware.Protected(), handler.UpdateUser)
	user.Delete("/:id", middleware.Protected(), handler.DeleteUser)

	app.Get("/", func(c *fiber.Ctx) error {
		err := middleware.FetchUserData(c, googleOauthConfig)

		if err != nil {
			fmt.Println("Failed to fetch user data:", err)
			return c.Redirect(fmt.Sprintf("%s/login", config.Config("FRONTEND_URL")))
		}

		status, ok := c.Locals("status").(string)
		if !ok {
			fmt.Println("Status not found in context or not a string")
			return c.Redirect(fmt.Sprintf("%s/login", config.Config("FRONTEND_URL")))
		}

		if status == "success" {
			return c.Redirect(fmt.Sprintf("%s/home", config.Config("FRONTEND_URL")))
		} else {
			return c.Redirect(fmt.Sprintf("%s/login", config.Config("FRONTEND_URL")))
		}
	})
}
