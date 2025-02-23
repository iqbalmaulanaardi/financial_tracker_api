package handler

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/t4ke0/financial_tracker_api/pkg/db"
	"github.com/t4ke0/financial_tracker_api/pkg/jwt_token"
)

type (
	Handler struct {
		PostgresLink string
		JWTsecret    string
	}
	//
	AuthRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	AuthLoginResponse struct {
		Token      string `json:"access_token"`
		ExpiredAt  string `json:"expired_at"`
		Expiration int64  `json:"expiration"`
	}
	LogoutRequest struct {
		Token string `json:"token"`
	}
	//
	FinanceType       string
	NewFinanceRequest struct {
		Title       string      `json:"title" example:"vacation finance"`
		Description string      `json:"description" example:"my vacation ...."`
		Type        FinanceType `json:"type" example:"income or expense"`
		Category    string      `json:"category" example:"vacation"`
		Amount      float32     `json:"amount" example:"420.69"`
	}
	NewFinanceResponse struct {
		FinanceId string `json:"finance_id"`
	}
	GetFinanceResponse struct {
		TotalExpense float32      `json:"total_expense"`
		TotalIncome  float32      `json:"total_income"`
		TotalBalance float32      `json:"totla_balance"`
		Result       []db.Finance `json:"result"`
		CurrentPage  int          `json:"current_page"`
		NextPage     int          `json:"next_page"`
		TotalPages   int          `json:"total_pages"`
	}
	PatchFinanceRequest struct {
		FinanceId string `json:"finance_id"`
		NewFinanceRequest
	}
	DeleteFinanceRequest struct {
		FinanceId string `json:"finance_id"`
	}
	//
	NewCustomCategoryRequest struct {
		Title string `json:"title"`
	}
	NewCustomCategoryResponse struct {
		Id string `json:"custom_category_id"`
	}
	Category struct {
		Id   string `json:"category_id"`
		Name string `json:"category_name"`
	}
	ListUserCustomCategoriesResponse struct {
		Categories []Category `json:"categories"`
	}
	DeleteCustomCategoryResponse struct {
		Id string `json:"id"`
	}
	//
	IssueMessage struct {
		Message string `json:"message"`
	}
)

const (
	FinanceTypeUndefined FinanceType = ""
	FinanceTypeExpense   FinanceType = "expense"
	FinanceTypeIncome    FinanceType = "income"
)

func (ft FinanceType) String() string {
	return string(ft)
}

func (n NewFinanceRequest) Validate() bool {
	return !(n.Title == "" || n.Type == FinanceTypeUndefined ||
		n.Category == "" || n.Amount <= 0)
}

func handleError(c *gin.Context) {
	if r := recover(); r != nil {
		c.JSON(http.StatusInternalServerError, IssueMessage{
			Message: fmt.Sprintf("Error: %v", r),
		})
	}
}

// HandleLogin
// @Summary Login
// @Description Login
// @Tags Authentication
// @Accept json
// @Param req body AuthRequest true "Login request"
// @Produce json
// @Success 200 {object} AuthLoginResponse
// @Failure 400
// @Failure 500
// @Router /login [post]
func (h Handler) HandleLogin(c *gin.Context) {
	var req AuthRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: "JSON request is not valid",
		})
		return
	}

	if req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: "JSON request is not valid",
		})
		return
	}

	defer handleError(c)

	repo, err := db.NewRepository(h.PostgresLink)
	if err != nil {
		panic(err)
	}
	defer repo.Close()

	u, err := repo.GetUser(req.Username)
	if err != nil {
		panic(err)
	}

	if !db.IsHashPasswordValid(u.Password, req.Password) {
		c.JSON(http.StatusUnauthorized, IssueMessage{
			Message: "username or password are incorrect!",
		})
		return
	}

	token, err := jwt_token.NewJWTtoken(h.JWTsecret, jwt_token.Claims{
		UserId: u.Id,
	})
	if err != nil {
		panic(err)
	}
	c.JSON(http.StatusOK, AuthLoginResponse{
		Token:      token,
		Expiration: jwt_token.GetTokenExpiration(),
		ExpiredAt: time.
			Now().
			AddDate(0, 0, jwt_token.ExpirationDays).
			Local().
			Format("02 Jan 2006 15:04:05"),
	})
}

// HandleRegister
// @Summary Register
// @Description Register
// @Tags Authentication
// @Accept json
// @Param req body AuthRequest true "Register request"
// @Success 201
// @Failure 400
// @Failure 500
// @Router /register [post]
func (h Handler) HandleRegister(c *gin.Context) {
	var req AuthRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: "JSON request is not valid",
		})
		return
	}

	if req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: "JSON request is not valid",
		})
		return
	}

	defer handleError(c)

	repo, err := db.NewRepository(h.PostgresLink)
	if err != nil {
		panic(err)
	}
	defer repo.Close()

	err = repo.CreateUser(req.Username, req.Password)
	if err != nil && err == db.ErrUserAlreadyExists {
		c.JSON(http.StatusConflict, IssueMessage{
			Message: "user already exists",
		})
		return
	}
	if err != nil {
		panic(err)
	}

	c.Status(http.StatusCreated)
}

// HandleLogout
// @Summary Logout
// @Description Logout
// @Tags Authentication
// @Accept json
// @Param req body LogoutRequest true "Logout request"
// @Success 200
// @Failure 400
// @Failure 500
// @Router /logout [post]
func (h Handler) HandleLogout(c *gin.Context) {
	var req LogoutRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: "JSON request is not valid",
		})
		return
	}

	if req.Token == "" {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: "JSON request is not valid",
		})
		return
	}

	defer handleError(c)

	repo, err := db.NewRepository(h.PostgresLink)
	if err != nil {
		panic(err)
	}
	defer repo.Close()

	revoked, err := repo.IsTokenRevoked(req.Token)
	if err != nil {
		panic(err)
	}

	if revoked {
		c.JSON(http.StatusConflict, IssueMessage{
			Message: "JWT token is already revoked!",
		})
		return
	}

	claims, err := jwt_token.ParseJWTtoken(h.JWTsecret, req.Token)
	if err != nil {
		panic(err)
	}

	if err := repo.InsertRevokedSession(claims.UserId, req.Token); err != nil {
		panic(err)
	}
}

// HandleNewFinance
// @Summary new finance
// @Description new finance
// @Tags Finance
// @Accept json
// @Param Authorization header string true "Authorization header"
// @Param request body NewFinanceRequest true "JSON body"
// @Success 201 {object} NewFinanceResponse
// @Failure 400
// @Failure 500
// @Router /new/finance [post]
func (h Handler) HandleNewFinance(c *gin.Context) {
	var req NewFinanceRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: fmt.Sprintf("%v", err),
		})
		return
	}

	if !req.Validate() {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: "JSON field is missing or not correct",
		})
		return
	}

	if req.Type != FinanceTypeExpense && req.Type != FinanceTypeIncome {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: "type need to be either expense / income",
		})
		return
	}

	defer handleError(c)

	repo, err := db.NewRepository(h.PostgresLink)
	if err != nil {
		panic(err)
	}
	defer repo.Close()

	fId := uuid.New().String()
	userId, ok := c.Keys["userid"]
	if !ok {
		c.JSON(http.StatusInternalServerError, IssueMessage{
			Message: "failed to get userid from the jwt token",
		})
		return
	}

	var categoryId string
	for i := 0; i < 2; i++ {
		switch i {
		case 0:
			categoryId, err = repo.IsMasterCategoryExists(req.Category, false)
			if err != nil {
				panic(err)
			}
		case 1:
			categoryId, err = repo.IsCustomCategory(userId.(string), req.Category)
			if err != nil {
				panic(err)
			}
		}
		if categoryId != "" {
			break
		}
	}

	if categoryId == "" {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: fmt.Sprintf("[%v] category cannot be find as custom or master category", req.Category),
		})
		return
	}

	if err := repo.CreateNewFinance(
		fId, userId.(string), req.Title, req.Description, req.Type.String(), categoryId, req.Amount,
	); err != nil {
		panic(err)
	}

	c.JSON(http.StatusCreated, NewFinanceResponse{
		FinanceId: fId,
	})
}

// HandleGetFinance
// @Summary get user finances
// @Description get user finances
// @Tags Finance
// @Accept json
// @Param Authorization header string true "Authorization header"
// @Param finance_id query string false "get single finance using finance_id"
// @Param title query string false "search by title"
// @Param sort-by-price query string false "sort by price ascending, descending"
// @Param start query string false "filter by start date"
// @Param end query string false "filter by end date"
// @Param item query integer false "amount of items in a single page"
// @Param page query integer false "page number to return"
// @Success 200 {object} GetFinanceResponse
// @Failure 400
// @Failure 500
// @Router /finance [get]
func (h Handler) HandleGetFinance(c *gin.Context) {

	itemStr, isItem := c.GetQuery("item")
	pageStr, isPage := c.GetQuery("page")

	var item, page int

	defer handleError(c)

	if !isItem {
		item = 3
	} else {
		var err error
		item, err = strconv.Atoi(itemStr)
		if err != nil {
			panic(err)
		}
	}

	if !isPage {
		page = 1
	} else {
		var err error
		page, err = strconv.Atoi(pageStr)
		if err != nil {
			panic(err)
		}
	}

	sortOrder, isSort := c.GetQuery("sort-by-price")

	financeId, isSingleFinanceId := c.GetQuery("finance_id")

	repo, err := db.NewRepository(h.PostgresLink)
	if err != nil {
		panic(err)
	}
	defer repo.Close()

	userIdAny := c.Keys["userid"]

	userId, ok := userIdAny.(string)
	if !ok {
		panic("type assertion user id")
	}

	if isSingleFinanceId {
		f, err := repo.GetFinance(userId, financeId)
		if err != nil {
			panic(err)
		}
		if f.Id == "" {
			c.JSON(http.StatusNotFound, IssueMessage{
				Message: fmt.Sprintf("couldn't find finance with %v id", financeId),
			})
			return
		}
		var expense float32
		var income float32
		if f.Type == FinanceTypeExpense.String() {
			expense = f.Amount
		} else if f.Type == FinanceTypeIncome.String() {
			income = f.Amount
		}
		c.JSON(http.StatusOK, GetFinanceResponse{
			TotalExpense: expense,
			TotalIncome:  income,
			TotalBalance: income - expense,
			Result:       []db.Finance{f},
			CurrentPage:  1,
			NextPage:     1,
			TotalPages:   1,
		})
		return
	}

	var totalIncome, totalExpense float32
	var results [][]db.Finance

	var finances []db.Finance
	for c := range FilterByDate(c, FilterByTitle(c, repo.GetUserFinances(userId, isSort, sortOrder))) {
		if c.Err != nil {
			panic(c.Err)
		}
		switch c.Finance.Type {
		case FinanceTypeExpense.String():
			totalExpense += c.Finance.Amount
		case FinanceTypeIncome.String():
			totalIncome += c.Finance.Amount
		}

		finances = append(finances, c.Finance)

		if len(finances) == item {
			results = append(results, finances)
			finances = nil
		}
	}

	if len(finances) != 0 {
		results = append(results, finances)
	}

	var pageRes []db.Finance
	var nextPage int

	if len(results) != 0 {

		if (len(results) - 1) < (page - 1) {
			pageRes = results[0]
		} else {
			pageRes = results[page-1]
		}

		if (page - 1) < len(results)-1 {
			nextPage = page + 1
		}

	}

	c.JSON(http.StatusOK, GetFinanceResponse{
		TotalIncome:  totalIncome,
		TotalExpense: totalExpense,
		TotalBalance: totalIncome - totalExpense,
		Result:       pageRes,
		CurrentPage:  page,
		NextPage:     nextPage,
		TotalPages:   len(results),
	})

}

func FilterByTitle(c *gin.Context, ch <-chan db.GetFinanceChan) <-chan db.GetFinanceChan {
	out := make(chan db.GetFinanceChan)
	title, isTitle := c.GetQuery("title")

	go func() {
		defer close(out)
		for o := range ch {
			if o.Err != nil {
				out <- o
				return
			}

			if !isTitle {
				out <- o
				continue
			}

			if strings.EqualFold(o.Title, title) {
				out <- o
				continue
			}

			reg := regexp.MustCompile(title)
			if reg.MatchString(o.Title) {
				out <- o
			}
		}
	}()

	return out
}

func FilterByDate(c *gin.Context, ch <-chan db.GetFinanceChan) <-chan db.GetFinanceChan {
	out := make(chan db.GetFinanceChan)
	startDate, isStartDate := c.GetQuery("start")
	endDate, isEndDate := c.GetQuery("end")

	go func() {
		defer close(out)
		for o := range ch {
			if o.Err != nil {
				out <- o
				return
			}
			if !isStartDate {
				out <- o
				continue
			}
			o.CreatedAt = o.CreatedAt.Local()
			parsedStart, err := time.Parse("2006-01-02", startDate)
			if err != nil {
				out <- db.GetFinanceChan{
					Err: err,
				}
				return
			}
			parsedStart = parsedStart.Local()
			start := time.Date(
				parsedStart.Year(), parsedStart.Month(), parsedStart.Day(),
				o.CreatedAt.Hour(), o.CreatedAt.Minute(), o.CreatedAt.Second(), o.CreatedAt.Nanosecond(), time.Local,
			)
			var parsedEnd time.Time
			if isEndDate {
				parsedEnd, err = time.Parse("2006-01-02", endDate)
				if err != nil {
					out <- db.GetFinanceChan{
						Err: err,
					}
					return
				}
				parsedEnd = parsedEnd.Local()
				end := time.Date(
					parsedEnd.Year(), parsedEnd.Month(), parsedEnd.Day(),
					o.CreatedAt.Hour(), o.CreatedAt.Minute(), o.CreatedAt.Second(), o.CreatedAt.Nanosecond(), time.Local,
				)
				if (o.CreatedAt.After(start) || o.CreatedAt.Equal(start)) && (o.CreatedAt.Before(end) || o.CreatedAt.Equal(end)) {
					out <- db.GetFinanceChan{
						Finance: o.Finance,
					}
				}
				continue
			}

			if o.CreatedAt.After(start) || o.CreatedAt.Equal(start) {
				out <- db.GetFinanceChan{
					Finance: o.Finance,
				}
			}
		}
	}()

	return out
}

// HandlePatchFinance
// @Summary patch user finances
// @Description patch user finances
// @Tags Finance
// @Accept json
// @Param Authorization header string true "Authorization header"
// @Param patchRequest body PatchFinanceRequest true "patch finance request"
// @Success 200
// @Failure 400
// @Failure 500
// @Router /finance [patch]
func (h Handler) HandlePatchFinance(c *gin.Context) {
	var req PatchFinanceRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: "JSON request is not valid",
		})
		return
	}

	if !req.Validate() || req.FinanceId == "" {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: "one or more JSON fields are missing!",
		})
		return
	}

	defer handleError(c)

	repo, err := db.NewRepository(h.PostgresLink)
	if err != nil {
		panic(err)
	}
	defer repo.Close()

	idInterface := c.Keys["userid"]

	userId, ok := idInterface.(string)
	if !ok {
		panic("type assertion user id from the context")
	}

	var categoryId string
	categoryId, err = repo.IsMasterCategoryExists(req.Category, false)
	if err != nil {
		panic(err)
	}

	if categoryId == "" {
		categoryId, err = repo.IsCustomCategory(userId, req.Category)
		if err != nil {
			panic(err)
		}
		if categoryId == "" {
			c.JSON(http.StatusBadRequest, IssueMessage{
				Message: fmt.Sprintf("couldn't find category id for [%v]", req.Category),
			})
			return
		}
	}

	if err := repo.PatchFinance(userId, db.Finance{
		Id:          req.FinanceId,
		Title:       req.Title,
		Description: req.Description,
		Type:        req.Type.String(),
		Category:    categoryId,
		Amount:      req.Amount,
	}); err != nil {
		panic(err)
	}

}

// HandleDeleteFinance
// @Summary delete user finances
// @Description delete user finances
// @Tags Finance
// @Accept json
// @Param Authorization header string true "Authorization header"
// @Param req body DeleteFinanceRequest true "delete finance request"
// @Success 200
// @Failure 400
// @Failure 500
// @Router /finance [delete]
func (h Handler) HandleDeleteFinance(c *gin.Context) {
	var req DeleteFinanceRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: "JSON request is not valid",
		})
		return
	}

	if req.FinanceId == "" {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: "one or more JSON fields are missing!",
		})
		return
	}

	defer handleError(c)

	idInterface := c.Keys["userid"]

	userId, ok := idInterface.(string)
	if !ok {
		panic("type assertion user id from the context")
	}

	repo, err := db.NewRepository(h.PostgresLink)
	if err != nil {
		panic(err)
	}
	defer repo.Close()

	if err := repo.DeleteFinance(userId, req.FinanceId); err != nil {
		panic(err)
	}
}

// HandleNewCustomCategory
// @Summary new custom category
// @Description new custom category
// @Tags Custom Categories
// @Accept json
// @Param Authorization header string true "Authorization header"
// @Param request body NewCustomCategoryRequest true "JSON body"
// @Success 201 {object} NewCustomCategoryResponse
// @Failure 400
// @Failure 401
// @Failure 500
// @Router /new/custom/category [post]
func (h Handler) HandleNewCustomCategory(c *gin.Context) {
	var req NewCustomCategoryRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: fmt.Sprintf("Invalid JSON %v", err),
		})
		return
	}

	if strings.TrimSpace(req.Title) == "" {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: "Invalid Request missing JSON field",
		})
		return
	}

	defer handleError(c)
	repo, err := db.NewRepository(h.PostgresLink)
	if err != nil {
		panic(err)
	}
	defer repo.Close()

	idInterface := c.Keys["userid"]

	userId, ok := idInterface.(string)
	if !ok {
		panic("type assertion user id from the context")
	}

	id, err := repo.NewCustomCategory(userId, req.Title)
	if err != nil && err == db.ErrCustomCategoryExists {
		c.JSON(http.StatusConflict, IssueMessage{
			Message: err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, NewCustomCategoryResponse{
		Id: id,
	})
}

// HandleGetCustomCategory
// @Summary list user custom & default categories
// @Description list user custom & default categories
// @Tags Custom Categories
// @Accept json
// @Param Authorization header string true "Authorization header"
// @Success 200 {object} ListUserCustomCategoriesResponse
// @Failure 400
// @Failure 401
// @Failure 500
// @Router /custom/category [get]
func (h Handler) HandleGetCustomCategory(c *gin.Context) {
	idInterface := c.Keys["userid"]

	defer handleError(c)

	userId, ok := idInterface.(string)
	if !ok {
		panic("type assertion user id from the context")
	}

	repo, err := db.NewRepository(h.PostgresLink)
	if err != nil {
		panic(err)
	}
	defer repo.Close()

	categories, err := repo.ListUserCustomCategory(userId)
	if err != nil {
		panic(err)
	}

	result := []Category{}

	for _, c := range categories {
		cId, err := repo.IsCustomCategory(userId, c)
		if err != nil {
			panic(err)
		}

		if cId == "" {
			continue
		}

		result = append(result, Category{
			Id:   cId,
			Name: c,
		})
	}

	for _, c := range db.DefaultCategories.Categories {
		cId, err := repo.IsMasterCategoryExists(c, false)
		if err != nil {
			panic(err)
		}
		if cId == "" {
			continue
		}
		result = append(result, Category{
			Id:   cId,
			Name: c,
		})
	}

	c.JSON(http.StatusOK, ListUserCustomCategoriesResponse{
		Categories: result,
	})
}

// HandleDeleteCustomCategory
// @Summary delete user custom category
// @Description delete user custom category
// @Tags Custom Categories
// @Param Authorization header string true "Authorization header"
// @Param custom_category_id query string true "custom category id"
// @Success 200 {object} DeleteCustomCategoryResponse
// @Failure 400
// @Failure 401
// @Failure 500
// @Router /custom/category [delete]
func (h Handler) HandleDeleteCustomCategory(c *gin.Context) {
	id, ok := c.GetQuery("custom_category_id")
	if !ok {
		c.JSON(http.StatusBadRequest, IssueMessage{
			Message: "missing category id",
		})
		return
	}

	defer handleError(c)

	idInterface := c.Keys["userid"]

	userId, ok := idInterface.(string)
	if !ok {
		panic("type assertion user id from the context")
	}

	repo, err := db.NewRepository(h.PostgresLink)
	if err != nil {
		panic(err)
	}
	defer repo.Close()

	if err := repo.DeleteCustomCategory(userId, id); err != nil {
		panic(err)
	}

	c.JSON(http.StatusOK, DeleteCustomCategoryResponse{
		Id: id,
	})
}

func CheckUserAuth(jwtSecret string, postgresLink string) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		defer handleError(c)

		repo, err := db.NewRepository(postgresLink)
		if err != nil {
			c.Abort()
			panic(err)
		}
		defer repo.Close()

		isRevoked, err := repo.IsTokenRevoked(token)
		if err != nil {
			c.Abort()
			panic(err)
		}

		if isRevoked {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims, err := jwt_token.ParseJWTtoken(jwtSecret, token)
		if err != nil {
			c.Abort()
			c.JSON(http.StatusUnauthorized, IssueMessage{
				Message: fmt.Sprintf("%v", err),
			})
			return
		}

		if claims.Expired {
			repo.InsertRevokedSession(claims.UserId, token)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Set("userid", claims.UserId)
		c.Next()
	}
}

func CorsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
	}
}
