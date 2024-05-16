package docsdemo

import (
	"errors"

	"fmt"

	"math/rand"

	"sync"

	"golang.org/x/crypto/bcrypt"
)

// User представляет собой структуру пользователя.

type User struct {
	ID string // ID пользователя

	Username string // Имя пользователя

	Password string // Пароль пользователя

	Role string // Роль пользователя

}

var users = make(map[string]*User)

var mu sync.Mutex // Mutex для синхронизации доступа к shared resource

// Register создает нового пользователя.

func Register(username, password, role string) error { // Добавлено параметр role

	if _, exists := users[username]; exists {

		return errors.New("пользователь с таким именем уже существует")

	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {

		return fmt.Errorf("ошибка при хешировании пароля: %v", err)

	}

	user := &User{

		ID: generateID(), // Предположим, что generateID() возвращает уникальный ID

		Username: username,

		Password: string(hashedPassword),

		Role: role, // Установка роли пользователя

	}

	users[user.ID] = user

	return nil

}

// Login проверяет имя пользователя и пароль.

func Login(username, password string) (*User, error) {

	user, ok := users[username]

	if !ok {

		return nil, errors.New("нет такого пользователя")

	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))

	if err != nil {

		return nil, errors.New("неверный пароль")

	}

	return user, nil

}

// CheckAccess проверяет права доступа пользователя.

func CheckAccess(userID string, requiredLevel string) bool {

	// Здесь должна быть логика проверки прав доступа пользователя.

	// Например, проверка роли пользователя и сравнение с требуемым уровнем доступа.

	// Для простоты мы просто проверяем, что уровень доступа пользователя соответствует требуемому.

	return users[userID].Role == requiredLevel

}

// generateID генерирует уникальный ID для пользователя.

// В реальной ситуации здесь должна быть реализована логика генерации уникального ID.

func generateID() string {

	return "user_" + fmt.Sprintf("%x", rand.Int63())

}

// UpdateUser обновляет информацию о пользователе.
func UpdateUser(id, newPassword, newRole string) error {
	mu.Lock()
	defer mu.Unlock()

	user, exists := users[id]
	if !exists {
		return errors.New("пользователь не найден")
	}

	if newPassword != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("ошибка при хешировании нового пароля: %v", err)
		}
		user.Password = string(hashedPassword)
	}

	if newRole != "" {
		user.Role = newRole
	}

	return nil
}

// DeleteUser удаляет пользователя по ID.
func DeleteUser(id string) error {
	mu.Lock()
	defer mu.Unlock()

	if _, exists := users[id]; !exists {
		return errors.New("пользователь не найден")
	}

	delete(users, id)
	return nil
}

// ChangePassword позволяет пользователю изменить свой пароль.
func ChangePassword(username, oldPassword, newPassword string) error {
	user, ok := users[username]
	if !ok {
		return errors.New("пользователь не найден")
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword))
	if err != nil {
		return errors.New("старый пароль неверен")
	}

	newHashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("ошибка при хешировании нового пароля: %v", err)
	}

	user.Password = string(newHashedPassword)
	return nil
}

// PromoteUser повышает роль пользователя до администратора.
func PromoteUser(id string) error {
	mu.Lock()
	defer mu.Unlock()

	user, exists := users[id]
	if !exists {
		return errors.New("пользователь не найден")
	}

	user.Role = "admin"
	return nil
}
