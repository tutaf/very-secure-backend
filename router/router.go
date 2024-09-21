package router

import (
	"app/config"
	"app/handler"
	"app/middleware"
	"context"
	"encoding/json"
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

	// Auth
	auth := api.Group("/authentication")
	auth.Post("/login", handler.Login)

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
			return c.Render("index", nil) // Render index if user data fetch fails
		}

		status, ok := c.Locals("status").(string)
		if !ok {
			fmt.Println("Status not found in context or not a string")
			return c.Render("index", nil)
		}

		if status == "success" {
			return c.Render("main_page", nil)
		} else {
			return c.Render("index", nil)
		}
	})

	app.Get("/auth/google", func(c *fiber.Ctx) error {
		url := googleOauthConfig.AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"))
		return c.Redirect(url)
	})

	app.Get("/auth/google/callback", func(c *fiber.Ctx) error {
		code := c.Query("code")
		if code == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "error", "message": "No code provided", "data": nil})
		}

		token, err := googleOauthConfig.Exchange(context.Background(), code)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Error while exchanging token", "data": nil})
		}

		client := googleOauthConfig.Client(context.Background(), token)

		// Fetch user info from Google
		resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Error fetching user info", "data": nil})
		}
		defer resp.Body.Close()

		var userInfo map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Error decoding user info", "data": nil})
		}

		middleware.SendCookie(c, token.AccessToken, token.RefreshToken)

		return c.Render("success", userInfo)
	})
}
