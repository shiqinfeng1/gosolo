// (c) 2019 Dapper Labs - ALL RIGHTS RESERVED

package engine

import (
	"context"
	"sync"
	"time"
)

// Unit handles synchronization management, startup, and shutdown for engines.
type Unit struct {
	admitLock sync.Mutex // used for synchronizing context cancellation with work admittance

	wg         sync.WaitGroup     // tracks in-progress functions
	ctx        context.Context    // context that is cancelled when the unit is Done
	cancel     context.CancelFunc // cancels the context
	sync.Mutex                    // can be used to synchronize the engine
}

// NewUnit returns a new unit.
func NewUnit() *Unit {

	ctx, cancel := context.WithCancel(context.Background())
	unit := &Unit{
		ctx:    ctx,
		cancel: cancel,
	}
	return unit
}

// wg加1
func (u *Unit) admit() bool {
	u.admitLock.Lock()
	defer u.admitLock.Unlock()

	select {
	case <-u.ctx.Done():
		return false
	default:
	}

	u.wg.Add(1)
	return true
}

// 通过ctx取消执行
func (u *Unit) stopAdmitting() {
	u.admitLock.Lock()
	defer u.admitLock.Unlock()

	u.cancel()
}

// Do synchronously executes the input function f unless the unit has shut down.
// It returns the result of f. If f is executed, the unit will not shut down
// until after f returns.
// 同步执行f函数，执行前wg加1 ，执行完成后，wg减1
func (u *Unit) Do(f func() error) error {
	if !u.admit() {
		return nil
	}

	defer u.wg.Done()
	return f()
}

// Launch asynchronously executes the input function unless the unit has shut
// down. If f is executed, the unit will not shut down until after f returns.
// 异步执行输入的f函数，执行前wg加1 ，执行完成后，wg减1
func (u *Unit) Launch(f func()) {
	if !u.admit() {
		return
	}

	go func() {
		defer u.wg.Done()
		f()
	}()
}

// LaunchAfter asynchronously executes the input function after a certain delay
// unless the unit has shut down.
// 在延时delay后，异步执行输入的f函数，执行前wg加1 ，执行完成后，wg减1
func (u *Unit) LaunchAfter(delay time.Duration, f func()) {
	u.Launch(func() {
		select {
		case <-u.ctx.Done():
			return
		case <-time.After(delay):
			f()
		}
	})
}

// LaunchPeriodically asynchronously executes the input function on `interval` periods
// unless the unit has shut down.
// If f is executed, the unit will not shut down until after f returns.
// 延时后以指定的interval间隔，异步执行输入的f函数，执行前wg加1 ，执行完成后，wg减1
func (u *Unit) LaunchPeriodically(f func(), interval time.Duration, delay time.Duration) {
	u.Launch(func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// 在等待延时期间，可能会停止运行
		select {
		case <-u.ctx.Done():
			return
		case <-time.After(delay):
		}

		for {
			select {
			case <-u.ctx.Done():
				return
			default:
			}

			select {
			case <-u.ctx.Done():
				return
			case <-ticker.C:
				f()
			}
		}
	})
}

// Ready returns a channel that is closed when the unit is ready. A unit is
// ready when the series of "check" functions are executed.
//
// The engine using the unit is responsible for defining these check functions
// as required.
// 当一系列指定的check完成后，关闭返回的channel
func (u *Unit) Ready(checks ...func()) <-chan struct{} {
	ready := make(chan struct{})
	go func() {
		for _, check := range checks {
			check()
		}
		close(ready)
	}()
	return ready
}

// Ctx returns a context with the same lifecycle scope as the unit. In particular,
// it is cancelled when Done is called, so it can be used as the parent context
// for processes spawned by any engine whose lifecycle is managed by a unit.
func (u *Unit) Ctx() context.Context {
	return u.ctx
}

// Quit returns a channel that is closed when the unit begins to shut down.
// ctx控制退出的channel
func (u *Unit) Quit() <-chan struct{} {
	return u.ctx.Done()
}

// Done returns a channel that is closed when the unit is done. A unit is done
// when (i) the series of "action" functions are executed and (ii) all pending
// functions invoked with `Do` or `Launch` have completed.
//
// The engine using the unit is responsible for defining these action functions
// as required.
// 先取消ctx，停止函数f的运行，然后执行action，最后等待函数f全部完成，全部完成后，关闭done的channel
func (u *Unit) Done(actions ...func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		u.stopAdmitting()
		for _, action := range actions {
			action()
		}
		u.wg.Wait()
		close(done)
	}()
	return done
}
