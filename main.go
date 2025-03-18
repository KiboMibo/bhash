// Package main предоставляет утилиту командной строки для работы с bcrypt хешированием.
// Она позволяет генерировать хеши паролей и проверять их валидность.
package main

import (
	"fmt"

	"github.com/spf13/pflag"
	"golang.org/x/crypto/bcrypt"
)

// main обрабатывает аргументы командной строки и выполняет соответствующие операции с bcrypt.
// Поддерживаются следующие операции:
// - Генерация хеша пароля
// - Проверка соответствия пароля и хеша
// - Получение стоимости (cost) хеша
func main() {
	// Определение флагов командной строки
	cost := pflag.IntP("cost", "c", 10, "Set bcrypt cost, default 10")
	pass := pflag.StringP("pass", "p", "", "Password to hash")
	hash := pflag.StringP("hash", "h", "", "Validate hash or get cost")

	pflag.Parse()

	// Проверка наличия необходимых аргументов
	if *pass == "" && *hash == "" {
		fmt.Println("Nothing to do. Exit")
		return
	}

	// Проверка соответствия пароля и хеша
	if *pass != "" && *hash != "" {
		if err := bcrypt.CompareHashAndPassword([]byte(*hash), []byte(*pass)); err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("Matched hash and pass")
		return
	}

	// Генерация хеша пароля
	if *pass != "" && *hash == "" {
		pHash, err := bcrypt.GenerateFromPassword([]byte(*pass), *cost)
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println(string(pHash))
		return
	}

	// Получение стоимости хеша
	if *pass == "" && *hash != "" {
		cost, err := bcrypt.Cost([]byte(*hash))
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Println("Cost is:", cost)
		return
	}
}
