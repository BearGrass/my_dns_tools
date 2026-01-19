package g53

//copy from fasthttp

type noCopy struct{} //nolint:unused

func (*noCopy) Lock()   {}
func (*noCopy) Unlock() {}
