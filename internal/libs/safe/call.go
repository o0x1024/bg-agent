// Copyright (c) 2016 - 2019 Sqreen. All Rights Reserved.
// Please refer to our terms for more information:
// https://www.sqreen.io/terms.html

package safe

import (
	"fmt"
	"github.com/pkg/errors"
	"reflect"
	"runtime"
)

// PanicError is an errors type wrapping a recovered panic value that happened
// during a function call.
type PanicError struct {
	// The function that was given to `Call()`.
	In func() error
	// The recovered panic value while executing `In()`.
	Err error
}

func NewPanicError(in func() error, err error) *PanicError {
	return &PanicError{
		In:  in,
		Err: errors.WithStack(err),
	}
}

func (e *PanicError) Unwrap() error {
	return e.Err
}

func (e *PanicError) Cause() error {
	return e.Err
}

func (e *PanicError) inName() string {
	return runtime.FuncForPC(reflect.ValueOf(e.In).Pointer()).Name()
}

func (e *PanicError) Error() string {
	return fmt.Sprintf("panic while executing %s: %#+v", e.inName(), e.Err)
}

// Call calls function `f` and recovers from any panic occurring while it
// executes, returning it in a `PanicError` object type.
func Call(f func() error) (err error) {
	defer func() {
		r := recover()
		if r == nil {
			// Note that panic(nil) matches this case and cannot be really tested for.
			return
		}

		switch actual := r.(type) {
		case error:
			err = actual
		case string:
			err = errors.New(actual)
			print(actual)
		default:
			err = errors.Errorf("%v", r)
		}

		err = NewPanicError(f, err)
	}()
	return f()
}
