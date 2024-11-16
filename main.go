package main

import (
	"database/sql"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db          *sql.DB
	jwtSecret   string
	tokenExpiry = time.Hour * 24 * 14 // 14 days
)

type Admin struct {
	Email     string `json:"email" binding:"required,email"`
	FirstName string `json:"fname" binding:"required"`
	LastName  string `json:"lname" binding:"required"`
	Password  string `json:"password" binding:"required"`
}

type Attendee struct {
	Email     string `json:"email" binding:"required,email"`
	FirstName string `json:"fname" binding:"required"`
	LastName  string `json:"lname" binding:"required"`
	Password  string `json:"password" binding:"required"`
	Address   string `json:"address" binding:"required"`
}

type Login struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func main() {
	if err := godotenv.Load(".env.local"); err != nil {
		log.Fatal("Error loading .env file")
	}

	var err error
	db, err = sql.Open("postgres", os.Getenv("SQL_URL"))
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	jwtSecret = os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET not set in environment variables")
	}

	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Content-Length", "Accept-Encoding", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	r.HandleMethodNotAllowed = true

	r.RedirectTrailingSlash = true

	r.GET("/hello", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"Hello": "World"})
	})

	r.GET("/robots.txt", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"User-agent": "*", "Disallow": "/"})
	})

	auth := r.Group("/auth")
	{
		auth.POST("/register-admin", registerAdmin)
		auth.POST("/register-attendee", registerAttendee)
		auth.POST("/login-admin", loginAdmin)
		auth.POST("/login-attendee", loginAttendee)
	}

	r.POST("/create-session", createSession)
	r.POST("/join-session", joinSession)
	r.POST("/active-sessions", activeSessions)
	r.POST("/get-sessions-created", getSessionsCreated)
	r.POST("/my-sessions", mySessions)
	r.POST("/get-session-attendees", getSessionAttendees)
	r.POST("/get-attended-sessions", getAttendedSessions)

	log.Fatal(r.Run(":8000"))
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

func createJWTToken(data map[string]interface{}) (string, error) {
	claims := jwt.MapClaims{}
	for k, v := range data {
		claims[k] = v
	}
	claims["exp"] = time.Now().Add(tokenExpiry).Unix()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func decodeJWTToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecret), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, jwt.ErrSignatureInvalid
	}

	return claims, nil
}

func registerAdmin(c *gin.Context) {
	var admin Admin
	if err := c.ShouldBindJSON(&admin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	admin.Email = strings.ToLower(admin.Email)
	hashedPassword, err := hashPassword(admin.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}

	var existingAdmin int
	err = db.QueryRow("SELECT 1 FROM Admins WHERE Email = $1", admin.Email).Scan(&existingAdmin)
	if err != sql.ErrNoRows {
		c.JSON(http.StatusConflict, gin.H{"error": "Admin already exists"})
		return
	}

	var adminID int
	err = db.QueryRow(
		"INSERT INTO Admins (Email, FirstName, LastName, Passwd) VALUES ($1, $2, $3, $4) RETURNING AdminID",
		admin.Email, admin.FirstName, admin.LastName, hashedPassword,
	).Scan(&adminID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving admin"})
		return
	}

	token, err := createJWTToken(map[string]interface{}{
		"id":    adminID,
		"email": admin.Email,
		"role":  "admin",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": token})
}

func registerAttendee(c *gin.Context) {
	var attendee Attendee
	if err := c.ShouldBindJSON(&attendee); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	attendee.Email = strings.ToLower(attendee.Email)
	hashedPassword, err := hashPassword(attendee.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}

	var existingAttendee int
	err = db.QueryRow("SELECT 1 FROM Attendees WHERE Email = $1", attendee.Email).Scan(&existingAttendee)
	if err != sql.ErrNoRows {
		c.JSON(http.StatusConflict, gin.H{"error": "Attendee already exists"})
		return
	}

	var attendeeID int
	err = db.QueryRow(
		"INSERT INTO Attendees (Email, Fname, Lname, Passwd, Address) VALUES ($1, $2, $3, $4, $5) RETURNING UniqueID",
		attendee.Email, attendee.FirstName, attendee.LastName, hashedPassword, attendee.Address,
	).Scan(&attendeeID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error saving attendee"})
		return
	}

	token, err := createJWTToken(map[string]interface{}{
		"id":    attendeeID,
		"email": attendee.Email,
		"role":  "attendee",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": token})
}

func loginAdmin(c *gin.Context) {
	loginUser(c, "Admins")
}

func loginAttendee(c *gin.Context) {
	loginUser(c, "Attendees")
}

func loginUser(c *gin.Context, tableName string) {
	var login Login
	if err := c.ShouldBindJSON(&login); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	login.Email = strings.ToLower(login.Email)
	var id int
	var fname, lname, hashedPassword string

	if tableName == "Admins" {
		err := db.QueryRow(
			"SELECT AdminID, FirstName, LastName, Passwd FROM Admins WHERE Email = $1",
			login.Email,
		).Scan(&id, &fname, &lname, &hashedPassword)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Invalid credentials"})
			return
		}
	} else {
		err := db.QueryRow(
			"SELECT UniqueID, Fname, Lname, Passwd FROM Attendees WHERE Email = $1",
			login.Email,
		).Scan(&id, &fname, &lname, &hashedPassword)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Invalid credentials"})
			return
		}
	}

	if !checkPasswordHash(login.Password, hashedPassword) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token, err := createJWTToken(map[string]interface{}{
		"id":    id,
		"email": login.Email,
		"role":  strings.ToLower(tableName[:len(tableName)-1]), // Trim "s" to get role
		"fname": fname,
		"lname": lname,
	})

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": token})
}

type SessionLocs struct {
	Address   string  `json:"address" binding:"required"`
	Longitude float64 `json:"longitude" binding:"required,gte=-180,lte=180"`
	Latitude  float64 `json:"latitude" binding:"required,gte=-90,lte=90"`
}

type CreateSessionInfo struct {
	Token     string        `json:"tok" binding:"required"`
	StartTime string        `json:"start_time" binding:"required"`
	EndTime   string        `json:"end_time" binding:"required"`
	Locations []SessionLocs `json:"locs" binding:"required"`
}

func createSession(c *gin.Context) {
	var sessionInfo CreateSessionInfo
	if err := c.ShouldBindJSON(&sessionInfo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims, err := decodeJWTToken(sessionInfo.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	role, ok := claims["role"].(string)
	if !ok || role != "admin" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid role"})
		return
	}

	adminID, ok := claims["id"].(float64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	startTime, err := time.Parse("2006-01-02 15:04:05", sessionInfo.StartTime)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid start time"})
		return
	}

	endTime, err := time.Parse("2006-01-02 15:04:05", sessionInfo.EndTime)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid end time"})
		return
	}

	if endTime.Before(startTime) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "End time is before start time"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error starting transaction"})
		return
	}

	var exists int
	tx.QueryRow(
		"SELECT 1 FROM Admins WHERE AdminID = $1",
		int(adminID),
	).Scan(&exists)

	if exists == 0 {
		tx.Rollback()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid admin"})
		return
	}

	var sessionID int = -1
	tx.QueryRow(
		"INSERT INTO Sessions (AdminID, StartTime, EndTime) VALUES ($1, $2, $3) RETURNING SessionID",
		int(adminID), startTime, endTime,
	).Scan(&sessionID)

	if sessionID == -1 {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating session"})
		return
	}

	for _, loc := range sessionInfo.Locations {
		tx.Exec(
			"INSERT INTO SessionLocations (SessionID, Address, Longitude, Latitude) VALUES ($1, $2, $3, $4)",
			sessionID, loc.Address, loc.Longitude, loc.Latitude,
		)
	}

	tx.Commit()

	c.JSON(http.StatusOK, gin.H{"result": "Session created successfully"})
}

type JoinSessionInfo struct {
	Token      string  `json:"tok" binding:"required"`
	SessionID  int     `json:"sessionid" binding:"required"`
	Latitude   float64 `json:"latitude" binding:"required,gte=-90,lte=90"`
	Longtitude float64 `json:"longitude" binding:"required,gte=-180,lte=180"`
}

func joinSession(c *gin.Context) {
	var joinInfo JoinSessionInfo
	if err := c.ShouldBindJSON(&joinInfo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	attendeeDetails, err := decodeJWTToken(joinInfo.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	role, ok := attendeeDetails["role"].(string)
	if !ok || role == "admin" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid role"})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error starting transaction"})
		return
	}

	var exists int = -1
	tx.QueryRow(
		"SELECT 1 FROM Attendees WHERE UniqueID = $1",
		attendeeDetails["id"],
	).Scan(&exists)

	if exists == -1 {
		tx.Rollback()
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid attendee"})
		return
	}

	var startTime, endTime time.Time
	tx.QueryRow(
		"SELECT StartTime, EndTime FROM Sessions WHERE SessionID = $1",
		joinInfo.SessionID,
	).Scan(&startTime, &endTime)

	if startTime.IsZero() || endTime.IsZero() {
		tx.Rollback()
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}

	var currentTime time.Time = time.Now()
	currentTime = currentTime.Add(5*time.Hour + 30*time.Minute)

	if currentTime.Before(startTime) || currentTime.After(endTime) {
		tx.Rollback()
		c.JSON(http.StatusForbidden, gin.H{"error": "Session is not active"})
		return
	}

	var longitude, latitude float64 = -1, -1
	tx.QueryRow(
		"SELECT Longitude, Latitude FROM SessionLocations WHERE SessionID = $1",
		joinInfo.SessionID,
	).Scan(&longitude, &latitude)

	if longitude == -1 || latitude == -1 {
		tx.Rollback()
		c.JSON(http.StatusNotFound, gin.H{"error": "Location not found"})
		return
	}

	if math.Abs(joinInfo.Latitude-latitude) > 0.001 || math.Abs(joinInfo.Longtitude-longitude) > 0.001 {
		tx.Rollback()
		c.JSON(http.StatusBadRequest, gin.H{"error": "You are not in the session location"})
		return
	}

	tx.Exec(
		"INSERT INTO Attended_By (UniqueID, SessionID) VALUES ($1, $2)",
		attendeeDetails["id"], joinInfo.SessionID,
	)
	tx.Exec(
		"INSERT INTO AttendeesLocations (LocationTimestamp, UniqueID, Longitude, Latitude) VALUES ($1, $2, $3, $4)",
		time.Now().In(time.FixedZone("Asia/Kolkata", 5*60*60+30*60)).Format("2006-01-02 15:04:05"), attendeeDetails["id"], joinInfo.Longtitude, joinInfo.Latitude,
	)

	tx.Commit()

	c.JSON(http.StatusOK, gin.H{"result": "Session joined successfully"})
}

type Identify struct {
	Token string `json:"tok" binding:"required"`
}

func activeSessions(c *gin.Context) {
	var identity Identify
	if err := c.ShouldBindJSON(&identity); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims, err := decodeJWTToken(identity.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	role, ok := claims["role"].(string)
	if !ok || (role != "admin" && role != "attendee") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "You are not authorized"})
		return
	}

	floatId, ok := claims["id"].(float64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid ID in token"})
		return
	}

	id := int(floatId)

	currentTime := time.Now().In(time.FixedZone("Asia/Kolkata", 5*60*60+30*60)).Format("2006-01-02 15:04:05")

	var attendedSessionIDs []int
	var rows *sql.Rows

	rows, err = db.Query("SELECT SessionID FROM Attended_By WHERE UniqueID = $1", id)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching attended sessions"})
		return
	}
	defer rows.Close()

	for rows.Next() {
		var sessionID int
		if err := rows.Scan(&sessionID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading session details"})
			return
		}

		attendedSessionIDs = append(attendedSessionIDs, sessionID)
	}

	var currentSessions []interface{}
	rows, err = db.Query("SELECT * FROM Sessions WHERE StartTime <= $1 AND EndTime > $1 ORDER BY StartTime DESC", currentTime)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching active sessions"})
		return
	}
	defer rows.Close()

	for rows.Next() {
		var sessionID int
		var adminID int
		var startTime, endTime time.Time
		if err := rows.Scan(&sessionID, &startTime, &endTime, &adminID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading session details"})
			return
		}

		var attended bool = false
		for _, id := range attendedSessionIDs {
			if id == sessionID {
				attended = true
				break
			}
		}

		if attended {
			continue
		}

		sessionLatitude, sessionLongitude := -1.0, -1.0
		db.QueryRow("SELECT Latitude, Longitude FROM SessionLocations WHERE SessionID = $1", sessionID).Scan(&sessionLatitude, &sessionLongitude)

		var tmp []interface{} = []interface{}{sessionID, startTime, endTime, adminID, sessionLatitude, sessionLongitude}
		currentSessions = append(currentSessions, tmp)
	}

	if len(currentSessions) == 0 {
		c.JSON(http.StatusOK, gin.H{"sessions": []interface{}{}})
	} else {
		c.JSON(http.StatusOK, gin.H{"sessions": currentSessions})
	}
}

func getSessionsCreated(c *gin.Context) {
	var identity Identify
	if err := c.ShouldBindJSON(&identity); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims, err := decodeJWTToken(identity.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	role, ok := claims["role"].(string)
	if !ok || role != "admin" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "You are not authorized"})
		return
	}

	floatAdminID, ok := claims["id"].(float64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid ID in token"})
		return
	}

	adminID := int(floatAdminID)

	rows, err := db.Query(
		"SELECT SessionID, StartTime, EndTime FROM Sessions WHERE AdminID = $1 ORDER BY StartTime DESC",
		adminID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching sessions"})
		return
	}
	defer rows.Close()

	var sessions []interface{}
	for rows.Next() {
		var sessionID int
		var startTime, endTime time.Time
		if err := rows.Scan(&sessionID, &startTime, &endTime); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading session details"})
			return
		}

		var tmp []interface{} = []interface{}{sessionID, startTime, endTime}
		sessions = append(sessions, tmp)
	}

	if len(sessions) == 0 {
		c.JSON(http.StatusOK, gin.H{"sessions": []interface{}{}})
	} else {
		c.JSON(http.StatusOK, gin.H{"sessions": sessions})
	}
}

func mySessions(c *gin.Context) {
	var identity Identify
	if err := c.ShouldBindJSON(&identity); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims, err := decodeJWTToken(identity.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	role, ok := claims["role"].(string)
	if !ok || role != "attendee" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "You are not authorized"})
		return
	}

	floatId, ok := claims["id"].(float64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid ID in token"})
		return
	}

	id := int(floatId)

	rows, err := db.Query(
		"SELECT Sessions.SessionID, Sessions.StartTime, Sessions.EndTime, Sessions.AdminID FROM Sessions, Attended_By WHERE Sessions.SessionID = Attended_By.SessionID AND Attended_By.UniqueID = $1",
		id,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching sessions"})
		return
	}
	defer rows.Close()

	var joinedSessions []interface{}

	for rows.Next() {
		var sessionID, adminID int
		var startTime, endTime time.Time
		if err := rows.Scan(&sessionID, &startTime, &endTime, &adminID); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading session details"})
			return
		}

		var tmp []interface{} = []interface{}{sessionID, startTime, endTime, adminID}
		joinedSessions = append(joinedSessions, tmp)
	}

	if len(joinedSessions) == 0 {
		c.JSON(http.StatusOK, gin.H{"sessions": []interface{}{}})
	} else {
		c.JSON(http.StatusOK, gin.H{"sessions": joinedSessions})
	}
}

type SessionDetails struct {
	Token     string `json:"tok" binding:"required"`
	SessionID int    `json:"sessionid" binding:"required"`
}

func getSessionAttendees(c *gin.Context) {
	var sessionDetails SessionDetails
	
	if err := c.ShouldBindJSON(&sessionDetails); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims, err := decodeJWTToken(sessionDetails.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	role, ok := claims["role"].(string)
	if !ok || role != "admin" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "You are not authorized"})
		return
	}

	floatAdminID, ok := claims["id"].(float64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid ID in token"})
		return
	}

	adminID := int(floatAdminID)

	var startTime, endTime time.Time
	var address string
	var latitude, longitude float64 = -360, -360

	type AttendeeDetails struct {
		Email     string `json:"email"`
		FirstName string `json:"fname"`
		LastName  string `json:"lname"`
	}

	var attendees []AttendeeDetails

	db.QueryRow(
		"SELECT StartTime, EndTime FROM Sessions WHERE SessionID = $1 AND AdminID = $2",
		sessionDetails.SessionID, adminID,
	).Scan(&startTime, &endTime)

	if startTime.IsZero() || endTime.IsZero() {
		c.JSON(http.StatusNotFound, gin.H{"error": "Session not found"})
		return
	}

	db.QueryRow(
		"SELECT Address, Longitude, Latitude FROM SessionLocations WHERE SessionID = $1",
		sessionDetails.SessionID,
	).Scan(&address, &longitude, &latitude)

	rows, err := db.Query(
		"SELECT Attendees.Email, Attendees.Fname, Attendees.Lname FROM Attendees, Attended_By WHERE Attendees.UniqueID = Attended_By.UniqueID AND Attended_By.SessionID = $1",
		sessionDetails.SessionID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching attendees"})
		return
	}
	defer rows.Close()

	for rows.Next() {
		var email, fname, lname string
		if err := rows.Scan(&email, &fname, &lname); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading attendee details"})
			return
		}

		attendees = append(attendees, AttendeeDetails{Email: email, FirstName: fname, LastName: lname})
	}

	if address == "" || latitude == -360 || longitude == -360 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Location not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"starttime": startTime, "endtime": endTime, "address": address, "latitude": latitude, "longitude": longitude, "attendees": attendees})
}

func getAttendedSessions(c *gin.Context) {
	var identity Identify
	if err := c.ShouldBindJSON(&identity); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	claims, err := decodeJWTToken(identity.Token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	role, ok := claims["role"].(string)
	if !ok || role != "attendee" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "You are not authorized"})
		return
	}

	floatId, ok := claims["id"].(float64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid ID in token"})
		return
	}

	id := int(floatId)

	var attendedSessions []interface{}
	rows, err := db.Query(
		"SELECT Sessions.SessionID, Sessions.StartTime, Sessions.EndTime, Sessions.AdminID, SessionLocations.Latitude, SessionLocations.Longitude FROM Sessions, Attended_By, SessionLocations WHERE Sessions.SessionID = Attended_By.SessionID AND Sessions.SessionID = SessionLocations.SessionID AND Attended_By.UniqueID = $1 ORDER BY Sessions.StartTime DESC",
		id,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error fetching attended sessions"})
		return
	}
	defer rows.Close()

	for rows.Next() {
		var sessionID, adminID int
		var startTime, endTime time.Time
		var latitude, longitude float64
		if err := rows.Scan(&sessionID, &startTime, &endTime, &adminID, &latitude, &longitude); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error reading session details"})
			return
		}

		var tmp []interface{} = []interface{}{sessionID, startTime, endTime, adminID, latitude, longitude}
		attendedSessions = append(attendedSessions, tmp)
	}

	if len(attendedSessions) == 0 {
		c.JSON(http.StatusOK, gin.H{"sessions": []interface{}{}})
	} else {
		c.JSON(http.StatusOK, gin.H{"sessions": attendedSessions})
	}
}
