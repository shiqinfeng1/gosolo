package infrastructure2

// Config encapsulation of configuration structs for all components related to xxx.
type Config struct {
	ReceivedMessageCacheSize int `mapstructure:"received-message-cache-size"`
}
