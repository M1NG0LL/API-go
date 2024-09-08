package main

import (
	"database/sql"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
)

type Account struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	IsActive  bool   `json:"is_active"`
}

var db *sql.DB
var jwtKey = []byte("secret_key") // Use a secure secret in production!

// JWT Claims structure
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func createTable() {
	query := `
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT,
        last_name TEXT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        is_active BOOLEAN
    );`
	_, err := db.Exec(query)
	if err != nil {
		log.Fatal(err)
	}
}

// POST
// Login function to generate JWT token
func login(c *gin.Context) {
	var account Account
	// Bind JSON to account struct
	if err := c.ShouldBindJSON(&account); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var dbAccount Account
	// Correct SQL query with parameter placeholders `?`
	err := db.QueryRow("SELECT * FROM accounts WHERE username = ?", account.Username).Scan(&dbAccount.ID, &dbAccount.FirstName, &dbAccount.LastName, &dbAccount.Username, &dbAccount.Email, &dbAccount.Password, &dbAccount.IsActive)

	// If the query returns an error or passwords don't match
	if err != nil || dbAccount.Password != account.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Create JWT token
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &Claims{
		Username: dbAccount.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not create token"})
		return
	}

	// Return the token
	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// Middleware to verify JWT token
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if len(tokenString) < 7 || tokenString[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header not provided or malformed"})
			c.Abort()
			return
		}

		tokenString = tokenString[7:] 

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		c.Set("username", claims.Username)
		c.Next() 
	}
}

// GET
// Create account
func createAccount(c *gin.Context) {
	var account Account
	if err := c.ShouldBindJSON(&account); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	query := "INSERT INTO accounts (first_name, last_name, username, email, password, is_active) VALUES (?, ?, ?, ?, ?, ?)"
	_, err := db.Exec(query, account.FirstName, account.LastName, account.Username, account.Email, account.Password, account.IsActive)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, account)
}

// GET
// get Account info using the Token
func getMyAccount(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var account Account
	err := db.QueryRow("SELECT * FROM accounts WHERE username = ?", username).Scan(&account.ID, &account.FirstName, &account.LastName, &account.Username, &account.Email, &account.Password, &account.IsActive)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, account)
}

// PUT
// Update Account info using the Token
func updateMyAccount(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var account Account
	if err := c.ShouldBindJSON(&account); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	query := "UPDATE accounts SET first_name = ?, last_name = ?, email = ?, password = ?, is_active = ? WHERE username = ?"
	_, err := db.Exec(query, account.FirstName, account.LastName, account.Email, account.Password, account.IsActive, username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, account)
}

// DELETE
// Delete Account info using the Token
func deleteMyAccount(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	query := "DELETE FROM accounts WHERE username = ?"
	_, err := db.Exec(query, username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Account deleted"})
}

// GET
// Get all Accounts using any token
func getAccounts(c *gin.Context) {
	rows, err := db.Query("SELECT * FROM accounts")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var accounts []Account
	for rows.Next() {
		var account Account
		if err := rows.Scan(&account.ID, &account.FirstName, &account.LastName, &account.Username, &account.Email, &account.Password, &account.IsActive); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		accounts = append(accounts, account)
	}
	c.JSON(http.StatusOK, accounts)
}

func main() {
	var err error
	db, err = sql.Open("sqlite3", "./accounts.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	createTable()

	r := gin.Default()

	r.POST("/login", login)
	r.POST("/accounts", createAccount)

	protected := r.Group("/")
	protected.Use(authMiddleware())

	protected.GET("/accounts/me", getMyAccount)
	protected.PUT("/accounts/me", updateMyAccount)
	protected.DELETE("/accounts/me", deleteMyAccount)

	protected.GET("/accounts", getAccounts)

	r.Run(":8080")
}
