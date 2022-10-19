// Copyright 2014 Manu Martinez-Almeida.  All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package gin

import (
	"bytes"
	"github.com/wsw365904/newcryptosm/http"
	"github.com/wsw365904/newcryptosm/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wsw365904/third_party/gin/binding"
)

func TestBindWith(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := CreateTestContext(w)

	c.Request, _ = http.NewRequest("POST", "/?foo=bar&bar=foo", bytes.NewBufferString("foo=unused"))

	var obj struct {
		Foo string `form:"foo"`
		Bar string `form:"bar"`
	}
	captureOutput(t, func() {
		assert.NoError(t, c.BindWith(&obj, binding.Form))
	})
	assert.Equal(t, "foo", obj.Bar)
	assert.Equal(t, "bar", obj.Foo)
	assert.Equal(t, 0, w.Body.Len())
}
