package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
)

func TestGenerateHash(t *testing.T) {
	// Сохраняем оригинальные аргументы и stdout
	oldArgs := os.Args
	oldStdout := os.Stdout
	defer func() {
		os.Args = oldArgs
		os.Stdout = oldStdout
	}()

	// Создаем буфер для захвата вывода
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Тест генерации хеша
	os.Args = []string{"cmd", "-p", "testpassword", "-c", "10"}

	// Запускаем main в горутине
	go main()

	// Закрываем writer
	w.Close()

	// Читаем вывод
	var buf bytes.Buffer
	buf.ReadFrom(r)
	hash := buf.String()

	// Проверяем, что хеш валидный
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("testpassword"))
	assert.NoError(t, err)
}

func TestValidateHash(t *testing.T) {
	// Сохраняем оригинальные аргументы
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()

	// Генерируем тестовый хеш
	hash, err := bcrypt.GenerateFromPassword([]byte("testpassword"), 10)
	assert.NoError(t, err)

	// Тест валидации хеша
	os.Args = []string{"cmd", "-p", "testpassword", "-h", string(hash)}
	main()

	// Проверяем, что хеш соответствует паролю
	err = bcrypt.CompareHashAndPassword(hash, []byte("testpassword"))
	assert.NoError(t, err)
}

func TestGetHashCost(t *testing.T) {
	// Сохраняем оригинальные аргументы и stdout
	oldArgs := os.Args
	oldStdout := os.Stdout
	defer func() {
		os.Args = oldArgs
		os.Stdout = oldStdout
	}()

	// Создаем буфер для захвата вывода
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Генерируем тестовый хеш
	hash, err := bcrypt.GenerateFromPassword([]byte("testpassword"), 10)
	assert.NoError(t, err)

	// Тест получения стоимости хеша
	os.Args = []string{"cmd", "-h", string(hash)}

	// Запускаем main в горутине
	go main()

	// Закрываем writer
	w.Close()

	// Читаем вывод
	var buf bytes.Buffer
	buf.ReadFrom(r)
	output := buf.String()

	// Проверяем, что стоимость равна 10
	cost, err := bcrypt.Cost(hash)
	assert.NoError(t, err)
	assert.Equal(t, 10, cost)
	assert.Contains(t, output, "Cost is: 10")
}
