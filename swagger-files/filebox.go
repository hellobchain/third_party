package swaggerFiles

import (
	"github.com/wsw365904/third_party/gin-swagger/webdav"
)

func NewHandler() *webdav.Handler {
	return &webdav.Handler{
		FileSystem: FS,
		LockSystem: webdav.NewMemLS(),
	}
}
