package updatable_configs

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrAlreadyRegistered is returned when a config field is registered with a name
// conflicting with an already registered config field.
// 模块自定义错误
var ErrAlreadyRegistered = fmt.Errorf("config name already registered")

// ValidationError is returned by a config setter function (Set*ConfigFunc) when
// the provided config field is invalid, and was not applied.
// 模块错误类型封装
type ValidationError struct {
	Err error
}

// 封装error接口的方法
func (err ValidationError) Error() string {
	return err.Err.Error()
}

// 生成一个新的验证错误的实例
func NewValidationErrorf(msg string, args ...any) ValidationError {
	return ValidationError{
		Err: fmt.Errorf(msg, args...),
	}
}

// 自定义error匹配判断
func IsValidationError(err error) bool {
	return errors.As(err, &ValidationError{})
}

// 任意类型的set和get函数的定义
type (
	SetAnyConfigFunc func(any) error
	GetAnyConfigFunc func() any
)

// The below are typed setter and getter functions for different config types.
//
// ADDING A NEW TYPE:
// If you need to add a new configurable config field with a type not below:
//  1. Add a new setter and getter type below
//  2. Add a Register*Config method to the Registrar interface and Manager implementation below
//  3. Add a TestManager_Register*Config test to the manager_test.go file.
//
// 具体类型的set和get函数的定义
type (
	// Set*ConfigFunc is a setter function for a single updatable config field.
	// Returns ValidationError if the new config value is invalid.

	SetUintConfigFunc     func(uint) error
	SetBoolConfigFunc     func(bool) error
	SetDurationConfigFunc func(time.Duration) error

	// Get*ConfigFunc is a getter function for a single updatable config field.

	GetUintConfigFunc     func() uint
	GetBoolConfigFunc     func() bool
	GetDurationConfigFunc func() time.Duration
)

// Field 代表一个动态的可配置的配置域.
type Field struct {
	// Name is the name of the config field, must be globally unique.
	Name string
	// TypeName is a human-readable string defining the expected type of inputs.
	TypeName string
	// Set is the setter function for the config field. It enforces validation rules
	// and applies the new config value.
	// Returns ValidationError if the new config value is invalid.
	Set SetAnyConfigFunc
	// Get is the getter function for the config field. It returns the current value
	// for the config field.
	Get GetAnyConfigFunc
}

// Manager manages setter and getter for updatable configs, across all components.
// Components register updatable config fields with the manager at startup, then
// the Manager exposes the ability to dynamically update these configs while the
// node is running, for example, via admin commands.
//
// The Manager maintains a list of type-agnostic updatable config fields. The
// typed registration function (Register*Config) is responsible for type conversion.
// The registration functions must convert input types (as parsed from JSON) to
// the Go type expected by the config field setter. They must also convert Go types
// from config field getters to displayable types (see structpb.NewValue for details).
type Manager struct {
	mu     sync.Mutex
	fields map[string]Field
}

func NewManager() *Manager {
	return &Manager{
		fields: make(map[string]Field),
	}
}

// GetField returns the updatable config field with the given name, if one exists.
func (m *Manager) GetField(name string) (Field, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	field, ok := m.fields[name]
	return field, ok
}

// AllFields returns all currently registered fields.
func (m *Manager) AllFields() []Field {
	m.mu.Lock()
	defer m.mu.Unlock()
	fields := make([]Field, 0, len(m.fields))
	for _, field := range m.fields {
		fields = append(fields, field)
	}
	return fields
}

var _ Registrar = (*Manager)(nil)

// Registrar provides an interface for registering config fields which can be
// dynamically updated while the node is running.
// Configs must have globally unique names. Setter functions are responsible for
// enforcing component-specific validation rules, and returning a ValidationError
// if the new config value is invalid.
type Registrar interface {
	// RegisterBoolConfig registers a new bool config.
	// Returns ErrAlreadyRegistered if a config is already registered with name.
	RegisterBoolConfig(name string, get GetBoolConfigFunc, set SetBoolConfigFunc) error
	// RegisterUintConfig registers a new uint config.
	// Returns ErrAlreadyRegistered if a config is already registered with name.
	RegisterUintConfig(name string, get GetUintConfigFunc, set SetUintConfigFunc) error
	// RegisterDurationConfig registers a new duration config.
	// Returns ErrAlreadyRegistered if a config is already registered with name.
	RegisterDurationConfig(name string, get GetDurationConfigFunc, set SetDurationConfigFunc) error
}

// RegisterBoolConfig registers a new bool config.
// Setter inputs must be bool-typed values.
// Returns ErrAlreadyRegistered if a config is already registered with name.
func (m *Manager) RegisterBoolConfig(name string, get GetBoolConfigFunc, set SetBoolConfigFunc) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.fields[name]; exists {
		return fmt.Errorf("can't register config %s: %w", name, ErrAlreadyRegistered)
	}

	field := Field{
		Name:     name,
		TypeName: "bool",
		Get: func() any {
			return get()
		},
		Set: func(val any) error {
			bval, ok := val.(bool)
			if !ok {
				return NewValidationErrorf("invalid type for bool config: %T", val)
			}
			return set(bval)
		},
	}
	m.fields[field.Name] = field
	return nil
}

// RegisterUintConfig registers a new uint config.
// Setter inputs must be float64-typed values and will be truncated if not integral.
// Returns ErrAlreadyRegistered if a config is already registered with name.
func (m *Manager) RegisterUintConfig(name string, get GetUintConfigFunc, set SetUintConfigFunc) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.fields[name]; exists {
		return fmt.Errorf("can't register config %s: %w", name, ErrAlreadyRegistered)
	}

	field := Field{
		Name:     name,
		TypeName: "uint",
		Get: func() any {
			return get()
		},
		Set: func(val any) error {
			fval, ok := val.(float64) // JSON numbers always parse to float64
			if !ok {
				return NewValidationErrorf("invalid type for bool config: %T", val)
			}
			return set(uint(fval))
		},
	}
	m.fields[field.Name] = field
	return nil
}

// RegisterDurationConfig registers a new duration config.
// Setter inputs must be duration-parseable string-typed values.
// Returns ErrAlreadyRegistered if a config is already registered with name.
func (m *Manager) RegisterDurationConfig(name string, get GetDurationConfigFunc, set SetDurationConfigFunc) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.fields[name]; exists {
		return fmt.Errorf("can't register config %s: %w", name, ErrAlreadyRegistered)
	}

	field := Field{
		Name:     name,
		TypeName: "duration",
		Get: func() any {
			val := get()
			return val.String()
		},
		Set: func(val any) error {
			sval, ok := val.(string)
			if !ok {
				return NewValidationErrorf("invalid type for duration config: %T", val)
			}
			dval, err := time.ParseDuration(sval)
			if err != nil {
				return NewValidationErrorf("unparseable duration: %s: %w", sval, err)
			}
			return set(dval)
		},
	}
	m.fields[field.Name] = field
	return nil
}
