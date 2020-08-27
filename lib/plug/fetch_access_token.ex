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
         _ <- Logger.debug("Extracted token: #{inspect(token)}"),
         {:ok, access_claims} <- Tokens.verify_token(token, oidc_name) do
      Logger.debug("[FetchAccessToken] Token signature valid, saving into conn.private")

      conn
      |> Tokens.put_claims_into_private(nil, access_claims)
    else
      true ->
        conn

      {:error, :verify, msg} ->
        Logger.error("[FetchAccessToken]: Error occured while verifying access token. Message: #{inspect(msg)}")

        conn

      all_else ->
        Logger.debug("[FetchAccessToken]: Acess token not found or invalid. reason: #{inspect(all_else)}")
        conn
    end
  end

  defp fetch_access_token(conn, :header) do
    case Conn.get_req_header(conn, "authorization") do
      [bearer_token | []] when is_binary(bearer_token) ->
        Logger.debug("[FetchAccessToken] Access token found in authorization header")
        {:ok, bearer_token}

      _ ->
        :error
    end
  end

  defp fetch_access_token(conn, :session) do
    case Tokens.get_access_token_from_session(conn) do
      nil ->
        :error

      token ->
        Logger.debug("[FetchAccessToken] Access token found in session")
        {:ok, token}
    end
  end
end
