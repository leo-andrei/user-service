package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
)

// UserProfile represents a user's profile information
type UserProfile struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Bio       string `json:"bio,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// SimpleStore is an in-memory data store for user profiles
type SimpleStore struct {
	profiles     map[int]UserProfile
	lastID       int
	profilesLock sync.RWMutex
}

// NewSimpleStore creates a new instance of SimpleStore
func NewSimpleStore() *SimpleStore {
	return &SimpleStore{
		profiles: make(map[int]UserProfile),
		lastID:   0,
	}
}

// Server encapsulates the HTTP server and data store
type Server struct {
	store       *SimpleStore
	router      *mux.Router
	jwtSecret   []byte
	serviceMesh bool
}

// NewServer creates a new instance of Server
func NewServer() *Server {
	// Get JWT secret from environment variable, or use a default for development
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "default-development-secret-do-not-use-in-production"
		log.Println("WARNING: Using default JWT secret. Set JWT_SECRET environment variable in production.")
	}

	// Check if we're running in a service mesh environment
	serviceMesh := os.Getenv("SERVICE_MESH_ENABLED") == "true"

	server := &Server{
		store:       NewSimpleStore(),
		router:      mux.NewRouter(),
		jwtSecret:   []byte(jwtSecret),
		serviceMesh: serviceMesh,
	}
	server.routes()
	return server
}

// LoggingMiddleware logs request details
func (s *Server) LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Request: %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// AuthenticationMiddleware verifies the JWT token
func (s *Server) AuthenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth check for health endpoint
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// Check for service mesh authentication
		if s.serviceMesh {
			// If running in service mesh, check for mesh-specific headers
			// e.g., X-Service-Mesh-ID or similar headers set by Istio/Linkerd
			meshAuthHeader := r.Header.Get("X-Service-Mesh-ID")
			internalServiceHeader := r.Header.Get("X-Internal-Service")

			// This is a simplified check - in production, validate these properly
			if meshAuthHeader != "" || internalServiceHeader != "" {
				log.Println("Request authenticated via service mesh")
				next.ServeHTTP(w, r)
				return
			}
		}

		// Verify JWT token (as backup or primary if not using service mesh)
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) < 8 || authHeader[:7] != "Bearer " {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		tokenString := authHeader[7:]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return s.jwtSecret, nil
		})

		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Extract claims if needed
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			// Set user ID in request context if needed
			log.Printf("Authenticated user with ID: %v", claims["sub"])
		}

		next.ServeHTTP(w, r)
	})
}

// routes sets up the HTTP routes for the server
func (s *Server) routes() {
	// Apply middleware to all routes
	s.router.Use(s.LoggingMiddleware)
	s.router.Use(s.AuthenticationMiddleware)

	// Main routes
	s.router.HandleFunc("/users", s.handleGetProfiles).Methods("GET")
	s.router.HandleFunc("/users", s.handleCreateProfile).Methods("POST")
	s.router.HandleFunc("/users/{id}", s.handleGetProfile).Methods("GET")
	s.router.HandleFunc("/users/{id}", s.handleUpdateProfile).Methods("PUT")
	s.router.HandleFunc("/users/{id}", s.handleDeleteProfile).Methods("DELETE")

	// Health check endpoint - often excluded from auth for monitoring
	s.router.HandleFunc("/health", s.handleHealthCheck).Methods("GET")
}

// handleHealthCheck responds with a simple health check status
func (s *Server) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "ok",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	})
}

// handleGetProfiles retrieves all user profiles
func (s *Server) handleGetProfiles(w http.ResponseWriter, r *http.Request) {
	s.store.profilesLock.RLock()
	defer s.store.profilesLock.RUnlock()

	profiles := make([]UserProfile, 0, len(s.store.profiles))
	for _, profile := range s.store.profiles {
		profiles = append(profiles, profile)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profiles)
}

// handleGetProfile retrieves a user profile by ID
func (s *Server) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid profile ID", http.StatusBadRequest)
		return
	}

	s.store.profilesLock.RLock()
	profile, ok := s.store.profiles[id]
	s.store.profilesLock.RUnlock()

	if !ok {
		http.Error(w, "Profile not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

// handleCreateProfile creates a new user profile
func (s *Server) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	var profile UserProfile
	if err := json.NewDecoder(r.Body).Decode(&profile); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.store.profilesLock.Lock()
	defer s.store.profilesLock.Unlock()

	// Generate a new ID
	s.store.lastID++
	profile.ID = s.store.lastID

	// Set timestamps
	now := time.Now().Format(time.RFC3339)
	profile.CreatedAt = now
	profile.UpdatedAt = now

	s.store.profiles[profile.ID] = profile

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(profile)
}

// handleUpdateProfile updates an existing user profile
func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid profile ID", http.StatusBadRequest)
		return
	}

	var updatedProfile UserProfile
	if err := json.NewDecoder(r.Body).Decode(&updatedProfile); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.store.profilesLock.Lock()
	defer s.store.profilesLock.Unlock()

	profile, ok := s.store.profiles[id]
	if !ok {
		http.Error(w, "Profile not found", http.StatusNotFound)
		return
	}

	// Update fields, keeping the original ID and created date
	updatedProfile.ID = profile.ID
	updatedProfile.CreatedAt = profile.CreatedAt
	updatedProfile.UpdatedAt = time.Now().Format(time.RFC3339)

	s.store.profiles[id] = updatedProfile

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedProfile)
}

// handleDeleteProfile deletes a user profile
func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, "Invalid profile ID", http.StatusBadRequest)
		return
	}

	s.store.profilesLock.Lock()
	defer s.store.profilesLock.Unlock()

	if _, ok := s.store.profiles[id]; !ok {
		http.Error(w, "Profile not found", http.StatusNotFound)
		return
	}

	delete(s.store.profiles, id)
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	// Start the server on port from environment or default to 9091
	port := os.Getenv("PORT")
	if port == "" {
		port = "9091"
	}

	server := NewServer()

	// Add some sample data
	server.store.profiles[1] = UserProfile{
		ID:        1,
		Username:  "johndoe",
		Email:     "john@example.com",
		FirstName: "John",
		LastName:  "Doe",
		CreatedAt: time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
		UpdatedAt: time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
	}
	server.store.lastID = 1

	fmt.Printf("User service starting on port %s...\n", port)
	log.Fatal(http.ListenAndServe(":"+port, server.router))
}
