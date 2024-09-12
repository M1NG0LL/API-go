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
	Balance   int	 `json:"balance"`
	IsActive  bool   `json:"is_active"`
	IsAdmin	  bool   `json:"is_admin"`
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
		balance INT DEFAULT 0,
        is_active BOOLEAN DEFAULT 0,
		is_admin BOOLEAN DEFAULT 0
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
	if err := c.ShouldBindJSON(&account); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var dbAccount Account
	err := db.QueryRow("SELECT id, first_name, last_name, username, email, password, balance, is_active, is_admin FROM accounts WHERE username = ?", account.Username).Scan(
		&dbAccount.ID, 
		&dbAccount.FirstName, 
		&dbAccount.LastName, 
		&dbAccount.Username, 
		&dbAccount.Email, 
		&dbAccount.Password, 
		&dbAccount.Balance, 
		&dbAccount.IsActive, 
		&dbAccount.IsAdmin,
	)

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
	err := db.QueryRow("SELECT id, first_name, last_name, username, email, password, balance, is_active, is_admin FROM accounts WHERE username = ?", username).Scan(
		&account.ID, 
		&account.FirstName, 
		&account.LastName, 
		&account.Username, 
		&account.Email, 
		&account.Password, 
		&account.Balance, 
		&account.IsActive, 
		&account.IsAdmin,
	)

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

	// Update the account information in the database
	query := `
		UPDATE accounts 
		SET first_name = ?, 
			last_name = ?, 
			email = ?, 
			password = ?, 
			is_active = ? 
		WHERE username = ?`
	_, err := db.Exec(query, account.FirstName, account.LastName, account.Email, account.Password, account.IsActive, username)
	
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Return the updated account information
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
		if err := rows.Scan(&account.ID, &account.FirstName, &account.LastName, &account.Username, &account.Email, &account.Password, &account.Balance, &account.IsActive, &account.IsAdmin,); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		accounts = append(accounts, account)
	}
	c.JSON(http.StatusOK, accounts)
}

// Balance functions

// POST
// Update the balance by adding money to it 
func deposit(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var amount struct {
		Amount int `json:"amount"`
	}

	// if err := c.ShouldBindJSON(&amount); err != nil || amount.Amount <= 0 {
	// 	c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid deposit amount"})
	// 	return
	// }

	query := "UPDATE accounts SET balance = balance + ? WHERE username = ?"
	_, err := db.Exec(query, amount.Amount, username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not deposit"})
		return
	}

	var newBalance int
	err = db.QueryRow("SELECT balance FROM accounts WHERE username = ?", username).Scan(&newBalance)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not retrieve updated balance"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"amount":  amount.Amount,
		"balance": newBalance,
		"message": "Deposit successful",
	})
}

// POST
// Update the balance by minusing money to it 
func withdraw(c *gin.Context) {
	username, exists := c.Get("username")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}

	var amount struct {
		Amount int `json:"amount"`
	}

	if err := c.ShouldBindJSON(&amount); err != nil || amount.Amount <= 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid withdrawal amount"})
		return
	}

	var currentBalance int
	err := db.QueryRow("SELECT balance FROM accounts WHERE username = ?", username).Scan(&currentBalance)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not retrieve balance"})
		return
	}

	if currentBalance < amount.Amount {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient funds"})
		return
	}

	query := "UPDATE accounts SET balance = balance - ? WHERE username = ?"
	_, err = db.Exec(query, amount.Amount, username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not withdraw"})
		return
	}

	var newBalance int
	err = db.QueryRow("SELECT balance FROM accounts WHERE username = ?", username).Scan(&newBalance)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not retrieve updated balance"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"amount":  amount.Amount,
		"balance": newBalance,
		"message": "Withdrawal successful",
	})
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

	// Money functions

	protected.POST("/accounts/deposit", deposit)
	protected.POST("/accounts/withdraw", withdraw)

	protected.GET("/accounts", getAccounts)

	r.Run(":8081")
}
