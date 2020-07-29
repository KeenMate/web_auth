defmodule WebAuth do
  def save_refresh_token(conn, refresh_token, expires_in) when is_binary(refresh_token) do
    WebAuth.Tokens.put_refresh_token_in_cookie(conn, refresh_token, expires_in)
  end
end
