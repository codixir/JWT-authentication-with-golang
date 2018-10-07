package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lib/pq"
	respond "gopkg.in/matryer/respond.v1"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Id       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

var db *sql.DB

func main() {
	pgUrl, err := pq.ParseURL("*************")

	if err != nil {
		log.Fatal(err)
	}

	db, err = sql.Open("postgres", pgUrl)

	if err != nil {
		log.Fatal(err)
	}

	err = db.Ping()

	if err != nil {
		log.Fatal(err)
	}

	router := mux.NewRouter()

	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(ProtectedEndpoint)).Methods("GET")

	log.Println("Listen on port 8000...")
	log.Fatal(http.ListenAndServe(":8000", router), "Server started on port 8000")
}

func GenerateToken(user User) (string, error) {
	var err error
	secret := "secret"

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
		// "exp": "123"
		// "nbf"
	})

	tokenString, err := token.SignedString([]byte(secret))

	if err != nil {
		log.Fatal(err)
	}

	return tokenString, nil
}

func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)

	if err != nil {
		log.Fatal(err)
	}

	user.Password = string(hash)
	token, err := GenerateToken(user)
	user.Token = token

	err = db.QueryRow("insert into users (email, password, token) values($1, $2, $3) RETURNING id;",
		user.Email, user.Password, user.Token).Scan(&user.Id)

	if err != nil {
		respond.With(w, r, http.StatusInternalServerError, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	user.Password = ""

	respond.With(w, r, http.StatusOK, user)
}

func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizationHeader := r.Header.Get("Authorization")

		if authorizationHeader != "" {
			if len(authorizationHeader) > 2 {
				token, error := jwt.Parse(authorizationHeader, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return []byte("secret"), nil
				})
				if error != nil {
					respond.With(w, r, http.StatusUnauthorized, error)
					return
				}
				if token.Valid {
					next.ServeHTTP(w, r)
				} else {
					respond.With(w, r, http.StatusUnauthorized, error)
					return
				}
			}
		} else {
			respond.With(w, r, http.StatusBadRequest, errors.New("req: Authrization header is missing"))
		}
	})
}

func ProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("test")
}

func ComparePasswords(hashedPssword string, password []byte) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPssword), password)

	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

func login(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)

	password := user.Password

	rows := db.QueryRow("select * from users where id=$1", user.Id)
	err := rows.Scan(&user.Id, &user.Email, &user.Password, &user.Token)

	hashedPassword := user.Password

	fmt.Println("hashedPassword ", hashedPassword)

	if err != nil {
		log.Fatal(err)
	}

	isValidPassword := ComparePasswords(hashedPassword, []byte(password))

	fmt.Println("isValidPassword ", isValidPassword)

	if isValidPassword {

		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Authorization", user.Token)

		json.NewEncoder(w).Encode(user.Token)
	} else {
		respond.With(w, r, http.StatusUnauthorized, err)
	}
}
