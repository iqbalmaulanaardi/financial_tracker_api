package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var ErrUserAlreadyExists error = errors.New("user already exists")
var ErrCustomCategoryExists error = errors.New("Custom Category Already Exists")

type MasterCategories struct {
	Categories []string `json:"master_categories"`
}

var DefaultCategories MasterCategories

type (
	Repository struct {
		conn   *sql.DB
		isMock bool
	}

	User struct {
		Id        string    `json:"id"`
		Username  string    `json:"username"`
		Password  string    `json:"password"`
		CreatedAt time.Time `json:"created_at"`
	}

	RevokedSession struct {
		UserId string
		Token  string
	}

	Finance struct {
		Id          string    `json:"id"`
		Title       string    `json:"title"`
		Description string    `json:"description"`
		Type        string    `json:"type"`
		Category    string    `json:"category"`
		Amount      float32   `json:"amount"`
		CreatedAt   time.Time `json:"created_at"`
	}
)

func NewRepository(postgresLink string) (Repository, error) {
	conn, err := sql.Open("postgres", postgresLink)
	if err != nil {
		return Repository{}, err
	}
	return Repository{
		conn: conn,
	}, nil
}

func (r Repository) CreateTables() error {
	_, err := r.conn.Exec(`
CREATE TABLE IF NOT EXISTS users (
	id VARCHAR NOT NULL,
	username VARCHAR NOT NULL,
	password VARCHAR NOT NULL,
	created_at timestamp
);


CREATE TABLE IF NOT EXISTS finances (
	id VARCHAR NOT NULL,
	user_id VARCHAR NOT NULL,
	title VARCHAR NOT NULL,
	description VARCHAR,
	amount DOUBLE PRECISION NOT NULL,
	type VARCHAR,
	category_id VARCHAR NOT NULL,
	created_at timestamp
);


CREATE TABLE IF NOT EXISTS master_categories (
	id VARCHAR NOT NULL,
	title VARCHAR NOT NULL,
	created_at timestamp
);

CREATE TABLE IF NOT EXISTS custom_categories (
	id VARCHAR NOT NULL,
	user_id VARCHAR NOT NULL,
	title VARCHAR NOT NULL,
	created_at timestamp
);

CREATE TABLE IF NOT EXISTS revoked_sessions (
	user_id varchar not null,
	token varchar not null
);`)
	if err != nil {
		return err
	}
	return nil
}

func (r Repository) Close() error {
	return r.conn.Close()
}

func hashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashed), nil
}

func IsHashPasswordValid(hashed, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)) == nil
}

func (r Repository) CreateUser(username string, password string) error {
	u, err := r.GetUser(username)
	if err != nil {
		return err
	}
	if u.Id != "" {
		return ErrUserAlreadyExists
	}
	userId := uuid.New().String()
	hashedPassword, err := hashPassword(password)
	if err != nil {
		return err
	}
	result, err := r.conn.Exec(
		`
INSERT
	INTO users(id, username, password, created_at)
	VALUES($1, $2, $3, $4)`, userId, username, hashedPassword, time.Now())
	if err != nil {
		return err
	}

	if n, _ := result.RowsAffected(); n == 0 {
		return fmt.Errorf("failed to insert new user into the database")
	}

	return nil
}

func (r Repository) GetUser(username string) (User, error) {
	strings.ToLower(username)
	user := User{}
	if err := r.conn.QueryRow(
		`
SELECT
	id, username, password, created_at
FROM 
	users
WHERE
	LOWER(username) = $1`, username).Scan(
		&user.Id, &user.Username,
		&user.Password, &user.CreatedAt,
	); err != nil && err != sql.ErrNoRows {
		return user, err
	}

	return user, nil
}

func (r Repository) InsertRevokedSession(userId, token string) error {
	result, err := r.conn.Exec(`
INSERT INTO revoked_sessions(user_id, token) VALUES($1, $2)`, userId, token)
	if err != nil {
		return err
	}

	if n, _ := result.RowsAffected(); n == 0 {
		return fmt.Errorf("failed to insert new revoked session into the db")
	}
	return nil
}

func (r Repository) GetRevokedSession(token string) (RevokedSession, error) {
	var rs RevokedSession
	err := r.conn.QueryRow(`
SELECT
	user_id, token
FROM
	revoked_sessions
WHERE token = $1`, token).Scan(
		&rs.UserId, &rs.Token,
	)
	if err != nil && err != sql.ErrNoRows {
		return rs, err
	}

	return rs, nil
}

func (r Repository) IsTokenRevoked(token string) (bool, error) {
	rs, err := r.GetRevokedSession(token)
	if err != nil {
		return false, err
	}

	if rs.UserId == "" && rs.Token == "" {
		return false, nil
	}

	return true, nil
}

func (r Repository) CreateNewFinance(
	id, userId string, title, description, typ, categoryId string, amount float32,
) error {
	result, err := r.conn.Exec(`
INSERT INTO 
	finances(id, user_id, title, description, amount, type, category_id, created_at)
	VALUES($1, $2, $3, $4, $5, $6, $7, $8)`,
		id, userId, title, description, amount, typ, categoryId, time.Now(),
	)
	if err != nil {
		return err
	}

	if n, _ := result.RowsAffected(); n == 0 {
		return fmt.Errorf("failed to insert new finance db")
	}

	return nil
}

func (r Repository) IsMasterCategoryExists(category string, insert bool) (string, error) {
	category = strings.ToLower(category)
	var (
		testTitle string
		testId    string
	)
	err := r.conn.QueryRow(`
SELECT id, title FROM master_categories WHERE title = $1`, category).Scan(&testId, &testTitle)
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}

	if insert && testTitle == "" {
		id := uuid.New().String()

		result, err := r.conn.Exec(`
		
		 INSERT INTO master_categories(id, title, created_at) VALUES($1, $2, $3)`,

			id, category, time.Now(),
		)
		if err != nil {
			return "", err
		}

		if n, _ := result.RowsAffected(); n == 0 {
			return "", fmt.Errorf("failed to insert master category")
		}

		return id, nil
	}

	return testId, nil
}

func (r Repository) IsCustomCategory(userId string, category string) (string, error) {
	category = strings.ToLower(category)
	var testId string
	err := r.conn.QueryRow(`
SELECT 
	id
FROM
	custom_categories
WHERE
	user_id = $1 AND title = $2`, userId, category).Scan(&testId)
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}

	return testId, nil
}

func (r Repository) GetCategoryName(categoryId string) (string, error) {
	var name string
	err := r.conn.QueryRow(`
SELECT
	title
FROM
	master_categories
WHERE
	id = $1`, categoryId).Scan(&name)
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}

	if name == "" {
		err = r.conn.
			QueryRow(`SELECT title FROM custom_categories WHERE id = $1`, categoryId).
			Scan(&name)
		if err != nil && err != sql.ErrNoRows {
			return "", err
		}
		if name == "" {
			return "", fmt.Errorf(
				"couldn't find category neither on master_categories nor custom_categories",
			)
		}
	}

	return name, nil

}

type GetFinanceChan struct {
	Finance

	Err error
}

func (r Repository) GetFinance(userId string, financeId string) (Finance, error) {
	finance := Finance{}
	err := r.conn.QueryRow(`
SELECT
	id, title, description, type, category_id, amount, created_at
FROM
	finances
WHERE
	user_id = $1 AND id = $2`, userId, financeId).Scan(
		&finance.Id,
		&finance.Title,
		&finance.Description,
		&finance.Type,
		&finance.Category,
		&finance.Amount,
		&finance.CreatedAt,
	)
	if err != nil && err != sql.ErrNoRows {
		return finance, err
	}

	if finance.Id == "" {
		return finance, nil
	}

	name, err := r.GetCategoryName(finance.Category)
	if err != nil {
		return finance, err
	}
	finance.Category = name

	return finance, nil
}

func (r Repository) GetUserFinances(userId string, sortByPrice bool, sortOrder string) <-chan GetFinanceChan {
	out := make(chan GetFinanceChan)

	var query string = `
SELECT
	id, title, description, type, category_id, amount, created_at
FROM
	finances
WHERE
	user_id = $1 ORDER BY
`

	var order string = "DESC"
	switch sortOrder {
	case "ascending":
		order = "ASC"
	case "descending":
		order = "DESC"
	}
	if sortByPrice {
		query += fmt.Sprintf(" amount %s", order)
	} else {
		query += fmt.Sprintf(" created_at %v", order)
	}

	go func() {
		defer close(out)
		rows, err := r.conn.Query(query, userId)

		if err != nil {
			out <- GetFinanceChan{
				Err: err,
			}
			return
		}
		defer rows.Close()
		for rows.Next() {
			var f Finance
			if err := rows.Scan(
				&f.Id, &f.Title, &f.Description,
				&f.Type, &f.Category, &f.Amount, &f.CreatedAt,
			); err != nil {
				out <- GetFinanceChan{
					Err: err,
				}
				return
			}

			name, err := r.GetCategoryName(f.Category)
			if err != nil {
				out <- GetFinanceChan{
					Err: err,
				}
				return
			}
			f.Category = name
			out <- GetFinanceChan{
				Finance: f,
			}
		}
	}()

	return out
}

func (r Repository) PatchFinance(userId string, f Finance) error {
	result, err := r.conn.Exec(`
UPDATE finances SET
	title = $1, description = $2, amount = $3, type = $4, category_id = $5
WHERE
	user_id = $6 AND id = $7`, f.Title, f.Description, f.Amount, f.Type, f.Category, userId, f.Id)
	if err != nil {
		return err
	}

	if n, _ := result.RowsAffected(); n == 0 {
		return fmt.Errorf("failed to patch finance with %v id", f.Id)
	}

	return nil
}

func (r Repository) DeleteFinance(userId, financeId string) error {
	result, err := r.conn.Exec(`
DELETE FROM finances
WHERE user_id = $1 AND id = $2`, userId, financeId)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return fmt.Errorf("failed to delete fianance with %v id", financeId)
	}
	return err
}

func (r Repository) NewCustomCategory(userId string, name string) (string, error) {
	test, err := r.IsCustomCategory(userId, name)
	if err != nil {
		return "", err
	}
	if test != "" {
		return "", ErrCustomCategoryExists
	}
	customId := uuid.New().String()
	result, err := r.conn.Exec(
		`INSERT INTO 
			custom_categories(id, user_id, title, created_at)
			VALUES($1, $2, $3, $4)`, customId, userId, name, time.Now())

	if err != nil {
		return "", err
	}

	if n, _ := result.RowsAffected(); n == 0 {
		return "", fmt.Errorf("failed to insert new custom category")
	}

	return customId, nil
}

// ListUserCustomCategory
func (r Repository) ListUserCustomCategory(userId string) ([]string, error) {
	rows, err := r.conn.Query(`
SELECT title FROM custom_categories WHERE user_id = $1`, userId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []string{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil && err != sql.ErrNoRows {
			return nil, err
		}

		out = append(out, c)
	}

	return out, nil
}

func (r Repository) DeleteCustomCategory(userId, categoryId string) error {
	const defaultCategory string = "others"
	defaultId, err := r.IsMasterCategoryExists(defaultCategory, false)
	if err != nil {
		return err
	}
	tx, err := r.conn.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`
UPDATE
	finances
SET
	category_id = $1
WHERE
	category_id = $2 AND user_id = $3`, defaultId, categoryId, userId); err != nil {
		tx.Rollback()
		return err
	}

	result, err := tx.Exec(`DELETE FROM custom_categories WHERE id = $1 AND user_id = $2`, categoryId, userId)
	if err != nil {
		tx.Rollback()
		return err
	}

	if n, _ := result.RowsAffected(); n == 0 {
		tx.Rollback()
		return fmt.Errorf("failed to delete custom category id %v", categoryId)
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}
