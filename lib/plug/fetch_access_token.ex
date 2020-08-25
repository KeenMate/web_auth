defmodule KeenAuth.Plug.FetchAccessToken do
  @moduledoc """
  Plug that verifies refresh token (if exists, redirects to login page otherwise) using openid connect
  """

  require Logger

  alias KeenAuth.Token
  alias KeenAuth.Session
  alias KeenAuth.Request

  def init(params) do
    %{
      fetch_from: Keyword.fetch!(params, :fetch_from),
      client: Keyword.fetch!(params, :client)
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

  def call(conn, %{fetch_from: target, client: client}) when is_atom(target) do
    with false <- Request.has_claims?(conn, client),
         {:ok, token} <- fetch_access_token(conn, client, target),
         {:ok, claims} <- Token.verify(token, client) do
      Logger.debug("[FetchAccessToken] Token signature valid, saving into conn.private")

      conn
      |> Request.put_claims(claims, client)
    else
      true ->
        Logger.debug("[FetchAccessToken] (#{target}): Claims already fetched, skipping")
        conn

      {:error, :verify, msg} ->
        Logger.error("[FetchAccessToken] (#{target}): Error occured while verifying access token. Message: #{inspect(msg)}")
        conn

      all_else ->
        Logger.debug("[FetchAccessToken] (#{target}): Acess token not found or invalid. reason: #{inspect(all_else)}")
        conn
    end
  end

  defp fetch_access_token(conn, client, :header) do
    Request.fetch_bearer_token(conn, client)
  end

  defp fetch_access_token(conn, client, :session) do
    case Session.get_access_token(conn, client) do
      nil -> :error
      token -> {:ok, token}
    end
  end
end
