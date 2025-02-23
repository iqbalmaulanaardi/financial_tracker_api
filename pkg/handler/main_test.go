package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
)

var testHandler Handler

var (
	postgresUsername = os.Getenv("POSTGRES_USER")
	postgresPassword = os.Getenv("POSTGRES_PASSWORD")
	postgresHost     = os.Getenv("POSTGRES_HOST")
	postgresDB       = os.Getenv("POSTGRES_DB")
	//
	postgresLink = fmt.Sprintf(
		"postgres://%s:%s@%s/%s?sslmode=disable",
		postgresUsername, postgresPassword,
		postgresHost, postgresDB,
	)
	jwtSecret = os.Getenv("JWT_SECRET")
	//
	testUsername string = "test-user-01"
	testPassword string = "user-password"
	//
	testAccessToken string
	//
	testFinanceTitle    string  = "finance-test-1"
	testFinanceCategory string  = "taxi"
	testFinanceAmount   float32 = 420.10
	testFinanceType     string  = "expense"
	//
	testFinanceId string
	//
	testCustomCategoryId    string
	testCustomCategoryTitle string = "new-category"
)

func TestRegisterUser(t *testing.T) {
	testHandler = Handler{
		PostgresLink: postgresLink,
		JWTsecret:    jwtSecret,
	}
	testEngine := gin.Default()
	testEngine.POST("/register", testHandler.HandleRegister)

	reqJSON := AuthRequest{
		Username: testUsername,
		Password: testPassword,
	}

	data, err := json.Marshal(reqJSON)
	if err != nil {
		t.Error(err)
		return
	}

	r, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(data))
	w := httptest.NewRecorder()

	testEngine.ServeHTTP(w, r)

	if w.Code != http.StatusCreated && w.Code != http.StatusConflict {
		t.Errorf("failed to register [%v] [%v]", w.Code, w.Body.String())
		return
	}
}

func TestLoginUser(t *testing.T) {
	testEngine := gin.Default()
	testEngine.POST("/login", testHandler.HandleLogin)

	reqJSON := AuthRequest{
		Username: testUsername,
		Password: testPassword,
	}

	data, err := json.Marshal(reqJSON)
	if err != nil {
		t.Error(err)
		return
	}

	r, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(data))
	w := httptest.NewRecorder()

	testEngine.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("failed to login %v %v", w.Code, w.Body.String())
		return
	}

	resp := AuthLoginResponse{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Error(err)
		return
	}

	testAccessToken = resp.Token
}

func TestCreateNewFinance(t *testing.T) {
	testEngine := gin.Default()
	testEngine.Use(CheckUserAuth(jwtSecret, postgresLink))
	testEngine.POST("/new/finance", testHandler.HandleNewFinance)

	reqJSON := NewFinanceRequest{
		Title:    testFinanceTitle,
		Type:     FinanceTypeExpense,
		Category: testFinanceCategory,
		Amount:   testFinanceAmount,
	}

	data, err := json.Marshal(reqJSON)
	if err != nil {
		t.Error(err)
		return
	}

	r, _ := http.NewRequest(http.MethodPost, "/new/finance", bytes.NewBuffer(data))
	r.Header.Set("Authorization", testAccessToken)
	w := httptest.NewRecorder()

	testEngine.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("failed to create finance  %v %v", w.Code, w.Body.String())
		return
	}

	resp := NewFinanceResponse{}

	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Error(err)
		return
	}

	testFinanceId = resp.FinanceId
}

func TestListFinance(t *testing.T) {
	testEngine := gin.Default()
	testEngine.Use(CheckUserAuth(jwtSecret, postgresLink))
	testEngine.GET("/finance", testHandler.HandleGetFinance)

	r, _ := http.NewRequest(http.MethodGet, "/finance", nil)
	r.Header.Set("Authorization", testAccessToken)
	w := httptest.NewRecorder()

	testEngine.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("failed to list finances %v %v", w.Code, w.Body.String())
		return
	}
}

func TestCreateCustomCategory(t *testing.T) {
	testEngine := gin.Default()
	testEngine.Use(CheckUserAuth(jwtSecret, postgresLink))
	testEngine.POST("/new/custom/category", testHandler.HandleNewCustomCategory)

	reqJSON := NewCustomCategoryRequest{
		Title: testCustomCategoryTitle,
	}

	data, err := json.Marshal(reqJSON)
	if err != nil {
		t.Error(err)
		return
	}

	r, _ := http.NewRequest(http.MethodPost, "/new/custom/category", bytes.NewBuffer(data))
	r.Header.Set("Authorization", testAccessToken)
	w := httptest.NewRecorder()

	testEngine.ServeHTTP(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("failed to create new custom category %v %v", w.Code, w.Body.String())
		return
	}

	resp := NewCustomCategoryResponse{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Error(err)
		return
	}

	testCustomCategoryId = resp.Id
}

func TestGetCustomCategory(t *testing.T) {
	testEngine := gin.Default()
	testEngine.Use(CheckUserAuth(jwtSecret, postgresLink))
	testEngine.GET("/custom/category", testHandler.HandleGetCustomCategory)

	r, _ := http.NewRequest(http.MethodGet, "/custom/category", nil)
	r.Header.Set("Authorization", testAccessToken)
	w := httptest.NewRecorder()

	testEngine.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("failed to list user category %v %v", w.Code, w.Body)
		return
	}
}

func TestDeleteCustomCategory(t *testing.T) {
	testEngine := gin.Default()
	testEngine.Use(CheckUserAuth(jwtSecret, postgresLink))
	testEngine.DELETE("/custom/category", testHandler.HandleDeleteCustomCategory)

	r, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("/custom/category?custom_category_id=%v", testCustomCategoryId), nil)
	r.Header.Set("Authorization", testAccessToken)
	w := httptest.NewRecorder()

	testEngine.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("failed to delete custom category %v %v", w.Code, w.Body.String())
	}
}

func TestDeleteFinance(t *testing.T) {
	testEngine := gin.Default()
	testEngine.Use(CheckUserAuth(jwtSecret, postgresLink))
	testEngine.DELETE("/finance", testHandler.HandleDeleteFinance)

	reqJSON := DeleteFinanceRequest{
		FinanceId: testFinanceId,
	}

	data, err := json.Marshal(reqJSON)
	if err != nil {
		t.Error(err)
		return
	}

	r, _ := http.NewRequest(http.MethodDelete, "/finance", bytes.NewBuffer(data))
	r.Header.Set("Authorization", testAccessToken)
	w := httptest.NewRecorder()

	testEngine.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("failed to delete finance %v %v", w.Code, w.Body.String())
		return
	}
}

func TestLogoutUser(t *testing.T) {
	testEngine := gin.Default()
	testEngine.POST("/logout", testHandler.HandleLogout)

	reqJSON := LogoutRequest{
		Token: testAccessToken,
	}

	data, err := json.Marshal(reqJSON)
	if err != nil {
		t.Error(err)
		return
	}

	r, _ := http.NewRequest(http.MethodPost, "/logout", bytes.NewBuffer(data))
	r.Header.Set("Authorization", testAccessToken)
	w := httptest.NewRecorder()

	testEngine.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("failed to logout %v %v", w.Code, w.Body.String())
		return
	}
}
