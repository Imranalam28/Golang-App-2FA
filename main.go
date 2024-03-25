package main

import (
    "fmt"
    "html/template"
    "log"
    "net/http"
    "github.com/pquerna/otp/totp"
)

type User struct {
    Username string
    Password string
    Secret   string
}

// Simple in-memory "database" for demonstration purposes
var users = map[string]*User{
    "john": {Username: "john", Password: "password", Secret: ""},
}

var templates = template.Must(template.ParseGlob("templates/*.html"))

func main() {
    http.HandleFunc("/", homeHandler)
    http.HandleFunc("/login", loginHandler)
    http.HandleFunc("/dashboard", dashboardHandler)
    http.HandleFunc("/generate-otp", generateOTPHandler)
	http.HandleFunc("/validate-otp", validateOTPHandler)


    fmt.Println("Starting server at :8080")
    log.Fatal(http.ListenAndServe(":8080", nil))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
    _ = templates.ExecuteTemplate(w, "index.html", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method == "GET" {
        _ = templates.ExecuteTemplate(w, "login.html", nil)
        return
    }

    r.ParseForm()
    username := r.Form.Get("username")
    password := r.Form.Get("password")

    user, ok := users[username]
    if !ok || user.Password != password {
        http.Redirect(w, r, "/login", http.StatusFound)
        return
    }

    if user.Secret == "" {
        http.Redirect(w, r, "/generate-otp?username="+username, http.StatusFound)
        return
    }
    _ = templates.ExecuteTemplate(w, "validate.html", struct{ Username string }{Username: username})
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
    username, err := r.Cookie("authenticatedUser")
    if err != nil || username.Value == "" {
        http.Redirect(w, r, "/", http.StatusFound)
        return
    }

    _ = templates.ExecuteTemplate(w, "dashboard.html", nil)
}

func generateOTPHandler(w http.ResponseWriter, r *http.Request) {
    username := r.URL.Query().Get("username")
    user, ok := users[username]
    if !ok {
        http.Redirect(w, r, "/", http.StatusFound)
        return
    }

    // Only generate the secret once
    if user.Secret == "" {
        secret, err := totp.Generate(totp.GenerateOpts{
            Issuer:      "Go2FADemo",
            AccountName: username,
        })
        if err != nil {
            http.Error(w, "Failed to generate TOTP secret.", http.StatusInternalServerError)
            return
        }
        user.Secret = secret.Secret()
    }

    otpURL := fmt.Sprintf("otpauth://totp/Go2FADemo:%s?secret=%s&issuer=Go2FADemo", username, user.Secret)
    data := struct {
        OTPURL   string
        Username string
    }{
        OTPURL:   otpURL,
        Username: username,
    }
    _ = templates.ExecuteTemplate(w, "qrcode.html", data)
}

func validateOTPHandler(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case "GET":
        // Extract the username from the query parameters, if needed
        username := r.URL.Query().Get("username")
        
        // Render the validate.html template, passing the username to it
        err := templates.ExecuteTemplate(w, "validate.html", struct{ Username string }{Username: username})
        if err != nil {
            http.Error(w, "Failed to render template", http.StatusInternalServerError)
        }

    case "POST":
        // Parsing form data
        if err := r.ParseForm(); err != nil {

            http.Error(w, "Error parsing form", http.StatusBadRequest)
            return
        }

        username := r.FormValue("username")
        otpCode := r.FormValue("otpCode")

        user, exists := users[username]
        if !exists {
            http.Error(w, "User does not exist", http.StatusBadRequest)
            return
        }

        // Using the TOTP library to validate the OTP code
        isValid := totp.Validate(otpCode, user.Secret)
        if !isValid {
            // If OTP validation fails, redirect back to the validation page
            http.Redirect(w, r, fmt.Sprintf("/validate-otp?username=%s", username), http.StatusTemporaryRedirect)
            return
        }

        // If OTP is valid, set a session cookie (simplified for this example) and redirect to dashboard
        http.SetCookie(w, &http.Cookie{
            Name:  "authenticatedUser",
            Value: "true",
            Path:  "/",
            MaxAge: 3600, // 1 hour for example
        })

        http.Redirect(w, r, "/dashboard", http.StatusSeeOther)

    default:
        http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
    }
}
