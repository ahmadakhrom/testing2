package database

import (
	"database/sql"
	"fmt"
	_"github.com/go-sql-driver/mysql"
)

//connecting db
func Connect() *sql.DB {
	db, err := sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/dbgolang") //3306 port don't change
	if err != nil {
		fmt.Print("db not connected")
	} else {
		fmt.Print("db connected")
	}
	err = db.Ping()
	fmt.Println(err)
	if err != nil {
		fmt.Println("db is not connected")
		fmt.Println(err.Error())
	}
	return db
}
