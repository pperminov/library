package libraryHttp

import (
	"net/http"
	url2 "net/url"
	"time"
)

var defaultClient *http.Client
var defaultTimeoutInSeconds int64 = 5

const defaultRetries int = 5

func init() {
	defaultClient = &http.Client{
		Timeout: time.Duration(defaultTimeoutInSeconds) * time.Second,
	}
}

func Do(req *http.Request) (*http.Response, error) {
	return do(req)
}

func GetUrl(ref string) (*http.Response, error) {
	url, err := url2.Parse(ref)
	if err != nil {
		return nil, err
	}
	req := http.Request{}
	req.Method = "GET"
	req.URL = url
	return do(&req)
}

func do(req *http.Request) (response *http.Response, err error) {
	attempts := defaultRetries
	if attempts < 1 {
		attempts = 1
	}

	canRetry := isIdempotent(req.Method)
	if req.Body != nil && req.GetBody == nil {
		canRetry = false
	}
	if !canRetry {
		attempts = 1
	}

	for i := attempts; i > 0; i-- {
		attemptReq := req
		if req.Body != nil && req.GetBody != nil {
			body, getErr := req.GetBody()
			if getErr != nil {
				return nil, getErr
			}
			attemptReq = req.Clone(req.Context())
			attemptReq.Body = body
		}
		response, err = defaultClient.Do(attemptReq)
		if err == nil {
			return response, nil
		}
	}
	return response, err
}

func isIdempotent(method string) bool {
	switch method {
	case "GET", "HEAD", "PUT", "DELETE", "OPTIONS":
		return true
	default:
		return false
	}
}
