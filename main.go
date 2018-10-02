package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

//Credential to generate token
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Token for respond
type Token struct {
	Token string `json:"token"`
}

const (
	secretKey = "WOW,MuchShibe,ToDogge" //SecretKey
)

func respondWithError(w http.ResponseWriter, code int, msg string) {
	respondWithJSON(w, code, map[string]string{"error": msg})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

func main() {

	r := mux.NewRouter()

	r.HandleFunc("/login", createToken).Methods("POST")
	r.HandleFunc("/cek", cekToken).Methods("GET")

	originsOk := handlers.AllowedOrigins([]string{"*"})
	headersOk := handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Accept", "Authorization"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "OPTIONS"})

	if err := http.ListenAndServe(":3000", handlers.CORS(originsOk, headersOk, methodsOk)(r)); err != nil {
		log.Fatal(err)
	}

}

func createToken(w http.ResponseWriter, r *http.Request) {
	var user Credential
	json.NewDecoder(r.Body).Decode(&user)
	createdToken, err := GenerateToken(user, []byte(secretKey))
	if err != nil {
		fmt.Println("Creating token failed")
	}
	jsonToken := &Token{
		Token: createdToken,
	}

	respondWithJSON(w, http.StatusOK, jsonToken)
}

func cekToken(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if CekToken(tokenString, secretKey) {
		w.WriteHeader(http.StatusOK)
	} else {
		respondWithError(w, http.StatusUnauthorized, "User Unauthorized")
	}
}

// GenerateToken for new login
func GenerateToken(user Credential, secretKey []byte) (string, error) {
	// Create the token
	token := jwt.New(jwt.SigningMethodHS256)
	// Set some claims
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	claims["username"] = user.Username
	claims["password"] = user.Password
	token.Claims = claims
	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(secretKey)
	return tokenString, err
}

// CekToken for cek user auth status
func CekToken(myToken string, myKey string) bool {
	token, err := jwt.Parse(myToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(myKey), nil
	})
	if err == nil && token.Valid {
		fmt.Println("Your token is valid.  I like your style.")
		return true
	} else {
		fmt.Println("This token is terrible!  I cannot accept this.")
		return false
	}
}

//HashPassword for hashing password
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

//CheckPasswordHash to cek if login
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
