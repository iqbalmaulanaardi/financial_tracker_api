package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	_ "github.com/t4ke0/financial_tracker_api/docs"
	"github.com/t4ke0/financial_tracker_api/pkg/db"
	"github.com/t4ke0/financial_tracker_api/pkg/handler"
)

var (
	port string = os.Getenv("PORT")
	//
	jwtSecret string = os.Getenv("JWT_SECRET")
	//
	postgresUsername string = os.Getenv("POSTGRES_USER")
	postgresPassword string = os.Getenv("POSTGRES_PASSWORD")
	postgresHost     string = os.Getenv("POSTGRES_HOST")
	postgresDB       string = os.Getenv("POSTGRES_DB")
	//
	postgresLink string = fmt.Sprintf(
		"postgres://%s:%s@%s/%s?sslmode=disable",
		postgresUsername, postgresPassword,
		postgresHost, postgresDB,
	)
	//
	skipDotEnv string = os.Getenv("SKIP_DOT_ENV")
)

//go:embed data.json
var categoriesData []byte

func loadDotEnvFile() error {
	log.Printf("[+] Loading .env File")
	if err := godotenv.Load(); err != nil {
		return err
	}
	port = os.Getenv("PORT")
	//
	jwtSecret = os.Getenv("JWT_SECRET")
	//
	postgresUsername = os.Getenv("POSTGRES_USER")
	postgresPassword = os.Getenv("POSTGRES_PASSWORD")
	postgresHost = os.Getenv("POSTGRES_HOST")
	postgresDB = os.Getenv("POSTGRES_DB")
	//
	postgresLink = fmt.Sprintf(
		"postgres://%s:%s@%s/%s?sslmode=disable",
		postgresUsername, postgresPassword,
		postgresHost, postgresDB,
	)
	log.Printf("[+] Postgres DSN %v", postgresLink)
	return nil
}

func init() {
	if skipDotEnv != "true" {
		if err := loadDotEnvFile(); err != nil {
			log.Fatal(err)
		}
	}
	if port == "" {
		port = "8080"
	}

	if err := json.Unmarshal(categoriesData, &db.DefaultCategories); err != nil {
		log.Fatal(err)
	}

	repo, err := db.NewRepository(postgresLink)
	if err != nil {
		log.Fatal(err)
	}
	defer repo.Close()

	if err := repo.CreateTables(); err != nil {
		log.Fatal(err)
	}

	for _, c := range db.DefaultCategories.Categories {
		categoryId, err := repo.IsMasterCategoryExists(c, true)
		if err != nil {
			log.Fatal(err)
		}
		if categoryId == "" {
			continue
		}
		log.Printf("CATEGORY [%v] |<>| ID [%v]", c, categoryId)
	}
}

// @title Swagger API
// @version 1.0
// @description financal tracker api.

// @host localhost:8080
// @BasePath /api/v1

func main() {
	engine := gin.Default()

	h := handler.Handler{postgresLink, jwtSecret}
	api := engine.Group("/api/v1")
	{
		api.GET("swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
		//
		api.POST("/login", h.HandleLogin)
		api.POST("/register", h.HandleRegister)
		api.POST("/logout", h.HandleLogout)
		//
		api.Use(handler.CheckUserAuth(jwtSecret, postgresLink))
		api.POST("/new/finance", h.HandleNewFinance)
		api.GET("/finance", h.HandleGetFinance)
		api.PATCH("/finance", h.HandlePatchFinance)
		api.DELETE("/finance", h.HandleDeleteFinance)
		//
		api.POST("/new/custom/category", h.HandleNewCustomCategory)
		api.GET("/custom/category", h.HandleGetCustomCategory)
		api.DELETE("/custom/category", h.HandleDeleteCustomCategory)
	}

	engine.Run(fmt.Sprintf(":%s", port))
}
