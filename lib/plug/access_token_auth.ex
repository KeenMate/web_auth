defmodule WebAuth.Plug.AccessTokenAuth do
  @moduledoc """
  Plug that verifies refresh token (if exists, redirects to login page otherwise) using openid connect
  """

  require Logger

  alias Plug.Conn
  alias WebAuth.Tokens

  def init(params) do
    params
  end

  def call(conn, _params) do
    with false <- Tokens.access_claims_in_private?(conn),
         false <- Tokens.access_claims_in_session?(conn) do
      access_token_circus(conn)
    else
      _ ->
        Logger.debug("[AccessTokenAuth]: Access claims are in private so no access token from header is extracted")
        conn
    end
  end

  def access_token_circus(conn) do
    with [bearer_token | []] when is_binary(bearer_token) <- Conn.get_req_header(conn, "authorization"),
         {:ok, access_claims} <- verify_access_token(bearer_token) do
      Logger.debug("[AccessTokenAuth]: Access token found in header")

      conn
      |> Tokens.put_claims_into_private(nil, access_claims)
      |> Tokens.put_claims_into_session(nil, access_claims)
    else
      _ ->
        conn
    end
  end

  defp verify_access_token("Bearer " <> token) do
    verify_access_token(token)
  end

  defp verify_access_token(token) when is_binary(token) do
    OpenIDConnect.verify(:keycloak, token)
  end
end
