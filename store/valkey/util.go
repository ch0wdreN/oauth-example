package valkey

import "fmt"

func accessTokenKey(signature string) string {
	return fmt.Sprintf("access_token:%s", signature)
}

func accessTokenSessionKey(signature string) string {
	return fmt.Sprintf("access_token_session:%s", signature)
}

func accessTokenClientKey(signature string) string {
	return fmt.Sprintf("access_token_client_id:%s", signature)
}

func refreshTokenKey(signature string) string {
	return "refresh_token:" + signature
}

func accessTokenRequestIDKey(requestID string) string {
	return fmt.Sprintf("access_token:requestID:%s", requestID)
}

func refreshTokenRequestIDKey(requestID string) string {
	return fmt.Sprintf("refresh_token:requestID:%s", requestID)
}

func authorizeCodeKey(code string) string {
	return fmt.Sprintf("authorize_code:%s", code)
}

func authorizeCodeSessionKey(code string) string {
	return fmt.Sprintf("authorize_code_session:%s", code)
}

func authorizeCodeClientKey(code string) string {
	return fmt.Sprintf("authorize_code_client_id:%s", code)
}
