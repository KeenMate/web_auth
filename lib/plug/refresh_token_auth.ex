defmodule WebAuth.Plug.RefreshTokenAuth do
  @moduledoc """
  Plug that verifies refresh token (if exists, redirects to login page otherwise) using openid connect
  """

  require Logger

  alias Plug.Conn
  alias WebAuth.Tokens
  alias WebAuth.Helpers.JwtHelpers

  def init(params) do
    %{
      audience: Keyword.fetch!(params, :audience)
    }
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
  def call(conn, %{audience: audience}) when is_binary(audience) do
    Logger.debug("[RefreshTokenAuth]: Claims not found in private. Circus is about to happen")

    with refresh_cookie_key <- Application.get_env(:babetti_web, :refresh_token_cookie, "rt"),
         {:ok, refresh_token} when is_binary(refresh_token) <- Map.fetch(conn.req_cookies, refresh_cookie_key),
         {:ok, tokens} <- get_tokens(refresh_token),
         {:ok, new_refresh_token} <- Map.fetch(tokens, "refresh_token"),
         {:ok, refresh_token_expiration} <- Map.fetch(tokens, "refresh_expires_in"),
         {:ok, new_access_token} <- Map.fetch(tokens, "access_token"),
         #  {:ok, id_claims} <- OpenIDConnect.verify(:keycloak, tokens["id_token"]),
         {:ok, access_claims} <- Tokens.verify_token(new_access_token) do
      Logger.debug("[RefreshTokenAuth]: Refresh token found in cookie and tokens fetched from keycloak and put into session")

      conn
      |> Tokens.put_refresh_token_in_cookie(new_refresh_token, refresh_token_expiration)
      |> Tokens.put_access_token_into_session(new_access_token)
      |> Tokens.put_claims_into_private(nil, access_claims)
    else
      err ->
        Logger.warn("[RefreshTokenAuth]: Circus might've ended prematurely. Reason: #{inspect(err)}")

        conn
    end
  end

  defp get_tokens(refresh_token) when is_binary(refresh_token) do
    with {:ok, tokens} <-
           OpenIDConnect.fetch_tokens(
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
