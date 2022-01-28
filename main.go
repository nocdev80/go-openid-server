package main

// docker run -d -p 6379:6379 redis
// docker run -d -p 27017:27017  mongo
import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nocdev80/go-openid-server/pkg/keytools"
	"github.com/nocdev80/go-openid-server/pkg/middleware"

	"github.com/gbrlsnchs/jwt/v3"
	"github.com/go-redis/redis"
	"github.com/google/uuid"

	"github.com/gorilla/mux"
)

var (
	baseurl string
	credis  *redis.Client
	priv    *rsa.PrivateKey
	pub     *rsa.PublicKey
)

type ClientConf struct {
	ClientID string `json:"clientID"`
	Secret   string `json:"secret"`
	Subject  string `json:"subject"`
}
type ProviderJSON struct {
	Issuer      string   `json:"issuer"`
	AuthURL     string   `json:"authorization_endpoint"`
	TokenURL    string   `json:"token_endpoint"`
	JWKSURL     string   `json:"jwks_uri"`
	UserInfoURL string   `json:"userinfo_endpoint"`
	Claims      []string `json:"claims_supported"`
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
func certs(w http.ResponseWriter, r *http.Request) {
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	p := map[string]interface{}{
		"keys": []map[string]string{
			{
				"e":   "AQAB",
				"kty": "RSA",
				"alg": "RS256",
				"n":   string(n),
				"use": "sig",
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

func auth(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	if !fileExists(clientID + ".json") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"Error": "ClientID  no exists"})
		return
	}
	file, err := os.Open(clientID + ".json")
	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}
	defer file.Close()
	str, err := ioutil.ReadAll(file)
	var clientConf ClientConf
	err = json.Unmarshal(str, &clientConf)
	if err != nil {
		json.NewEncoder(w).Encode(err)
		return
	}

	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	scope := r.URL.Query().Get("scope")
	state := r.URL.Query().Get("state")

	if credis.HGet(clientID, "client_id").Val() != "" {
		http.Redirect(w, r, redirectURI+"?code="+credis.HGet(clientID, "code").Val()+"&state="+credis.HGet(clientID, "state").Val(), http.StatusTemporaryRedirect)
		log.Println("ttl:", credis.TTL(clientID).Val().String())
		return
	}

	code := uuid.New().String()
	credis.HSet(clientID, "client_id", clientID)
	credis.HSet(clientID, "client_secret", clientConf.Secret)
	credis.HSet(clientID, "redirect_uri", redirectURI)
	credis.HSet(clientID, "response_type", responseType)
	credis.HSet(clientID, "scope", scope)
	credis.HSet(clientID, "state", state)
	credis.HSet(clientID, "code", code)
	credis.HSet(clientID, "subject", clientConf.Subject)
	credis.Expire(clientID, 600*time.Second)

	log.Println("auth code:", code, " url:", redirectURI+"?code="+code+"&state="+state, " ttl:", credis.TTL(clientID).Val().String())

	// esta redireccion la tiene que hacer el adaptive
	http.Redirect(w, r, redirectURI+"?code="+code+"&state="+state, http.StatusTemporaryRedirect)

	// aca va la direccion con el adaptive
	// TODO: hacer un endpoint para consultar el code ge ;ude ser un uuid generado aca guardado en redis para que despues se pueda validar en el token

}

func token(w http.ResponseWriter, r *http.Request) {

	authorization := r.Header.Get("Authorization")
	authorizationToken := strings.Split(authorization, " ")[1]

	clientIDSecret, err := base64.StdEncoding.DecodeString(authorizationToken)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(err)
		log.Println(err)
		return
	}

	clientID := strings.Split(string(clientIDSecret), ":")[0]
	secret := strings.Split(string(clientIDSecret), ":")[1]
	secretSave := credis.HGet(clientID, "client_secret").Val()

	if secretSave != secret {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(errors.New("secret not found "))
		log.Println("secret not found ")
		return
	}
	if r.PostFormValue("grant_type") != "authorization_code" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(errors.New("grant_type should be authorization_code"))
		log.Println("grant_type should be authorization_code")
		return
	}

	code := r.PostFormValue("code")
	log.Println("code:", code)
	log.Println("code:", credis.HGet(clientID, "code").Val())
	if code != credis.HGet(clientID, "code").Val() {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(errors.New("code not found"))
		log.Println("code not found")
		return
	}

	pAccessToken := r.URL.Query().Get("access_token")
	if pAccessToken == "" {
		pAccessToken = r.FormValue("access_token")
		if pAccessToken == "" {
			pAccessToken = r.PostForm.Get("access_token")
		}
	}

	if pAccessToken != "" {
		log.Println("token ttl:", credis.TTL(pAccessToken).String())
		value := credis.Get(pAccessToken)
		ret := map[string]interface{}{
			"id_token":     value.String(),
			"access_token": pAccessToken,
			"token_type":   "Bearer",
			"expires_in":   credis.TTL(pAccessToken).Val().Seconds(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(ret)
		return
	}
	type CustomPayload struct {
		jwt.Payload
		Foo string `json:"foo,omitempty"`
		Bar int    `json:"bar,omitempty"`
	}

	var hs = jwt.NewRS256(jwt.RSAPrivateKey(priv))
	now := time.Now()
	jwtID := uuid.New()
	pl := CustomPayload{
		Payload: jwt.Payload{
			Issuer:         baseurl,
			Subject:        credis.HGet(clientID, "subject").Val(),
			Audience:       jwt.Audience{clientID},
			ExpirationTime: jwt.NumericDate(now.Add(600 * time.Second)),
			IssuedAt:       jwt.NumericDate(now),
			JWTID:          jwtID.String(),
		},
	}

	token, _ := jwt.Sign(pl, hs)

	accessToken := uuid.New()

	credis.Set(accessToken.String(), string(token), 600*time.Second)
	ret := map[string]interface{}{
		"id_token":     string(token),
		"access_token": accessToken.String(),
		"token_type":   "Bearer",
		"expires_in":   credis.TTL(pAccessToken).Val().Seconds(),
	}
	credis.Expire(clientID, 600*time.Second)

	//log.Println("new token:", credis.TTL(accessToken.String()).String())
	//log.Println("session:", credis.TTL(clientID).String())

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ret)

}

func configuration(w http.ResponseWriter, r *http.Request) {
	p := ProviderJSON{
		Issuer:      baseurl,
		AuthURL:     baseurl + "/o/oauth2/v2/auth",
		TokenURL:    baseurl + "/token",
		JWKSURL:     baseurl + "/oauth2/v3/certs",
		UserInfoURL: baseurl + "/v1/userinfo",
		Claims:      []string{"aud", "email", "email_verified", "exp", "family_name", "given_name", "iat", "iss", "locale", "name", "picture", "sub"},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p)
}

func userinfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode("")
}

// Handle404 is Handler for notound resource http
func Handle404() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//log.Println(">>>>>>", r.URL.Path, "  >m>", r.Method)
		json.
			NewEncoder(w).
			Encode(r.URL)
	})
}

func main() {
	var addr string
	var redisConn string
	var redisPassword string

	flag.StringVar(&baseurl, "baseur", "http://127.0.0.1:8000", "baseurl")
	flag.StringVar(&addr, "addr", ":8000", "addr")
	flag.StringVar(&redisConn, "rconn", "127.0.0.1:6379", "redis Connection")
	flag.StringVar(&redisPassword, "rpass", "", "redis password")

	flag.Parse()
	log.Println("S-OpenID v0.0.1")

	credis = redis.NewClient(&redis.Options{
		Addr:     redisConn,
		Password: redisPassword, // no password set
		DB:       0,             // use default DB
	})

	r := mux.NewRouter()
	//fileServer := http.FileServer(http.Dir("./site"))

	r.HandleFunc("/token", token).Methods(http.MethodPost)
	r.HandleFunc("/o/oauth2/v2/auth", auth).Methods(http.MethodGet)
	r.HandleFunc("/oauth2/v3/certs", certs).Methods(http.MethodGet)
	r.HandleFunc("/v1/userinfo", userinfo).Methods(http.MethodGet)
	r.HandleFunc("/.well-known/openid-configuration", configuration).Methods(http.MethodGet)
	r.NotFoundHandler = Handle404()

	r.Use(middleware.Log)
	//r.PathPrefix("/").Handler(http.StripPrefix("/", fileServer))
	log.Println("Server on port " + addr)

	priv, pub = keytools.GenerateRsaKeyPair()

	srv := &http.Server{
		Handler:      r,
		Addr:         addr,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())

}
