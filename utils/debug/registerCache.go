package debug

type registerCache interface {
	Get(owner, key string) (value []byte, found bool)
	Set(owner, key string, value []byte)
	Persist() error
}
