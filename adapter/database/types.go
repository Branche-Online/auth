package database

// DbDriverType is a type that represents the database driver type
// It is used to specify the database driver type when creating a new database connection
// It is used to create a new database connection using the gorm library
type DbDriverType string

// Supported database driver types
const (
	PGSQL   DbDriverType = "pgsql"
	MYSQL   DbDriverType = "mysql"
	MARIADB DbDriverType = "mariadb"
	SQLITE  DbDriverType = "sqlite"
)
