package model

import (
	"gorm.io/gorm"
	"time"
)

type RefreshToken struct {
	gorm.Model
	Token     string    `gorm:"not null"`
	UserID    uint      `gorm:"not null"`
	ExpiresAt time.Time `gorm:"not null"`
	User      User      `gorm:"foreignKey:UserID"`
}
