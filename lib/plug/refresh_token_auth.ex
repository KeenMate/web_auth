defmodule KeenAuth.Plug.RefreshTokenAuth do
  @moduledoc """
  Plug that verifies refresh token (if exists, redirects to login page otherwise) using openid connect
  """

  require Logger

  alias Plug.Conn
  alias KeenAuth.Session
  alias KeenAuth.Token
  alias KeenAuth.Request

  def init(params) do
    %{client: Keyword.fetch!(params, :client)}
  end

  def call(%Conn{private: %{access_claims: _}} = conn, _params) do
    conn
  end

  # todo: Make sure that no redundant operations are involved
  def call(conn, %{client: client}) do
    Logger.debug("[RefreshTokenAuth] No claims found, retrieving new access token")

    with refresh_token when is_binary(refresh_token) <- Session.get_refresh_token(conn, client),
         {:ok, tokens} <- Token.refresh(refresh_token, client),
         {:ok, claims} <- Token.verify(tokens["access_token"], client) do
      conn
      |> Session.create(tokens, client)
      |> Request.put_claims(claims, client)
    else
      nil ->
        Logger.debug("[RefreshTokenAuth] No refresh token in cookie, skipping")
        conn

      err ->
        Logger.warn("[RefreshTokenAuth] Refresh error. Reason: #{inspect(err)}")
        conn
    end
  end
end
