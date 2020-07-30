defmodule WebAuth.Plug.FetchAccessToken do
  @moduledoc """
  Plug that verifies refresh token (if exists, redirects to login page otherwise) using openid connect
  """

  require Logger

  alias Plug.Conn
  alias WebAuth.Tokens

  def init(params) do
    %{
      fetch_from: Keyword.fetch!(params, :fetch_from),
      oidc_name: Keyword.fetch!(params, :oidc_name)
    }
  end

  def call(conn, %{fetch_from: []}) do
    conn
  end

  def call(conn, %{fetch_from: [target | rest]} = params) do
    conn
    |> call(%{params | fetch_from: target})
    |> call(%{params | fetch_from: rest})
  end

  def call(conn, %{fetch_from: target, oidc_name: oidc_name}) when is_atom(target) do
    with false <- Tokens.access_claims_in_private?(conn),
         {:ok, token} <- fetch_access_token(conn, target),
         {:ok, access_claims} <- Tokens.verify_token(token, oidc_name) do
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
end
