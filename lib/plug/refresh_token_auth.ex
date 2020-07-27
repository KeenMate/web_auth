defmodule WebAuth.Plug.RefreshTokenAuth do
  @moduledoc """
  Plug that verifies refresh token (if exists, redirects to login page otherwise) using openid connect
  """

  require Logger

  alias Plug.Conn
  alias WebAuth.Tokens

  def init(params) do
    params
  end

  def call(
        %Conn{
          private: %{
            access_claims: _
          }
        } = conn,
        _params
      ) do
    Logger.debug("[RefreshTokenAuth]: Claims found in private. No refresh token circus made")
    conn
  end

  # todo: Make sure that no redundant operations are involved
  def call(conn, _params) do
    with false <- Tokens.access_claims_in_private?(conn),
         false <- Tokens.access_claims_in_session?(conn) do
      Logger.debug("[RefreshTokenAuth]: Claims not found in private. Circus is about to happen")
      refresh_token_circus(conn)
    else
      _ ->
        conn
    end
  end

  defp refresh_token_circus(conn) do
    with refresh_cookie <- Application.get_env(:babetti_web, :refresh_token_cookie, "rt"),
         refresh_token when is_binary(refresh_token) <- conn.req_cookies[refresh_cookie],
         {:ok, tokens} <- get_tokens(refresh_token),
         {:ok, id_claims} <- OpenIDConnect.verify(:keycloak, tokens["id_token"]),
         {:ok, access_claims} <- OpenIDConnect.verify(:keycloak, tokens["access_token"])do
      Logger.debug("[RefreshTokenAuth]: Refresh token found in cookie and tokens fetched from keycloak and put into session")

      conn
      |> Tokens.put_tokens_into_session(tokens)
      |> Tokens.put_claims_into_session(id_claims, access_claims)
      |> Tokens.put_claims_into_private(id_claims, access_claims)
    else
      err ->
        Logger.warn("[RefreshTokenAuth]: Circus might ended prematurely. Reason: #{inspect(err)}")
        conn
      #        |> BabettiWeb.LoginController.login_user(params)
      #        |> Conn.halt()
      #        conn
      #        |> Plug.Conn.send_resp(401, "Unauthorized")
      #        |> Plug.Conn.halt()
    end
  end

  defp get_tokens(refresh_token) when is_binary(refresh_token) do
    with {:ok, tokens} <- OpenIDConnect.fetch_tokens(
      :keycloak,
      %{
        grant_type: "refresh_token",
        refresh_token: refresh_token
      }
    ) do
      {:ok, tokens}
    end
  end
end
