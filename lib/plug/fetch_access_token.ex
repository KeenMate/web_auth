defmodule WebAuth.Plug.FetchAccessToken do
  @moduledoc """
  Plug that verifies refresh token (if exists, redirects to login page otherwise) using openid connect
  """

  require Logger

  alias Plug.Conn
  alias WebAuth.Tokens
  alias WebAuth.Helpers.JwtHelpers

  def init(params) do
    Keyword.fetch!(params, :fetch_from)
  end

  def call(conn, []) do
    conn
  end

  def call(conn, [target | rest]) do
    conn
    |> call(target)
    |> call(rest)
  end

  def call(conn, target) when is_atom(target) do
    with false <- Tokens.access_claims_in_private?(conn),
         {:ok, token} <- fetch_access_token(conn, target),
         {:ok, access_claims} <- verify_access_token(token),
         # TODO: add audience as params
         :ok <- JwtHelpers.validate_claims(access_claims, "babetti") do
      conn
      |> Tokens.put_claims_into_private(nil, access_claims)
    else
      true ->
        conn

      _ ->
        Logger.debug("[AccessTokenAuth]: Acess token not found or invalid")
        conn
    end
  end

  defp fetch_access_token(conn, :header) do
    case Conn.get_req_header(conn, "authorization") do
      [bearer_token | []] when is_binary(bearer_token) -> {:ok, bearer_token}
      _ -> :error
    end
  end

  defp fetch_access_token(conn, :session) do
    case Tokens.get_access_token_from_session(conn) do
      nil -> :error
      token -> {:ok, token}
    end
  end

  defp verify_access_token("Bearer " <> token) do
    verify_access_token(token)
  end

  defp verify_access_token(token) when is_binary(token) do
    OpenIDConnect.verify(:keycloak, token)
  end
end
