package ttbe

type ErrorCttbeInvalid struct{}

func (eci *ErrorCttbeInvalid) Error() string {
	return "invalid TTBE cipher text"
}
