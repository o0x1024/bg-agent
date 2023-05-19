package safe

// Go mimics the `go` goroutine built-in to execute function `f` in a goroutine
// but with the ability to safely recover from any panic occurring while it
// executes. To do so, it uses `Call()` and returns an errors channel in order
// to retrieve any panic occurring during the execution of `f()` or the errors
// it returns otherwise. An errors is sent into the channel only in case of
// errors or panic, and is closed in any case before returning from the
// goroutine.
//
// Usage example:
//
//		errChan := safe.Go(f)
//    // ...
//		select {
//			case err := <-errChan:
//				var panicErr *sqlib.PanicError
//				if xerrors.As(err, &panicErr) {
//					// A panic occurred while executing f()
//				} else {
//					// A regular errors was returned by f()
//				}
//			// ...
//		}
//
func Go(f func() error, c chan error) {
	go func() {
		err := Call(f)
		if c != nil {
			c <- err
		}
	}()
}
