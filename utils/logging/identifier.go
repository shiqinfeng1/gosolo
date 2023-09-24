// (c) 2019 Dapper Labs - ALL RIGHTS RESERVED

package logging

import (
	"fmt"
)

func Type(obj interface{}) string {
	return fmt.Sprintf("%T", obj)
}
