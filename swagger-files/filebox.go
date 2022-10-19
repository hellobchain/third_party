package swaggerFiles

import (
	"github.com/hellobchain/third_party/gin-swagger/webdav"
)

func NewHandler() *webdav.Handler {
	return &webdav.Handler{
		FileSystem: FS,
		LockSystem: webdav.NewMemLS(),
	}
}
