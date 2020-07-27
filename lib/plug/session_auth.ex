defmodule WebAuth.Plug.SessionAuth do
  @moduledoc """
  Plug that verifies refresh token (if exists, redirects to login page otherwise) using openid connect
  """

  require Logger

  alias WebAuth.Tokens

  def init(params) do
    params
  end

  def call(conn, _params) do
    with false <- Tokens.access_claims_in_private?(conn),
         false <- Tokens.access_claims_in_session?(conn) do
      session_circus(conn)
    else
      _ ->
        Logger.debug("[SessionAuth]: Claims found so no id token from session is extracted")
        conn
    end
  end

  defp session_circus(conn) do
    with id_token when is_binary(id_token) <- Plug.Conn.get_session(conn, :id_token),
         {:ok, id_claims} <- OpenIDConnect.verify(:keycloak, id_token),
         access_token when is_binary(access_token) <- Plug.Conn.get_session(conn, :access_token),
         {:ok, access_claims} <- OpenIDConnect.verify(:keycloak, access_token) do
      Logger.debug("[SessionAuth]: ID token found in existing session")

      conn
      |> Tokens.put_claims_into_session(id_claims, access_claims)
      |> Tokens.put_claims_into_private(id_claims, access_claims)
    else
      _ ->
        conn
    end
  end

#  defp into_tokens_map(id_token, refresh_token, access_token) do
#    %{"id_token" => id_token, "refresh_token" => refresh_token, "access_token" => access_token}
#  end
end
