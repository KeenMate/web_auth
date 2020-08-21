defmodule WebAuth.Session do
  require Logger
  alias Plug.Conn
  alias WebAuth.Helpers.Date
  alias WebAuth.Helpers.JwtHelpers

  @access_claims_key :access_claims
  @access_token_key :access_token

  def create_from_callback(conn, params, client) when is_atom(client) do
    with {:ok, tokens} <- OpenIDConnect.fetch_tokens(client, params) do
      create(conn, tokens, client)
    end
  end

  def create(conn, %{"access_token" => access_token} = tokens, client) when is_atom(client) do
    with {:ok, claims} <- OpenIDConnect.verify(client, access_token) do
      conn
      |> put_tokens(tokens, client)
      |> put_claims(claims, client)
    end
  end

  def destroy(conn, client) do
    conn
    |> delete_claims(client)
    |> delete_tokens(client)
  end

  def put_claims(conn, claims, _client) do
    Conn.put_session(conn, @access_claims_key, claims)
  end

  def delete_claims(conn, _client) do
    Conn.delete_session(conn, @access_claims_key)
  end

  def put_tokens(conn, tokens, client) do
    conn
    |> put_access_token(tokens, client)
    |> put_refresh_token(tokens, client)
  end

  def delete_tokens(conn, client) do
    conn
    |> delete_access_token(client)
    |> delete_refresh_token(client)
  end

  defp put_access_token(conn, %{"access_token" => access_token}, client) do
    put_access_token(conn, access_token, client)
  end

  defp put_access_token(conn, access_token, _client) when is_binary(access_token) do
    Conn.put_session(conn, @access_token_key, access_token)
  end

  defp delete_access_token(conn, _client) do
    Conn.delete_session(conn, @access_token_key)
  end

  defp put_refresh_token(conn, %{"refresh_token" => refresh_token}, client) do
    put_refresh_token(conn, refresh_token, client)
  end

  defp put_refresh_token(conn, refresh_token, client) when is_binary(refresh_token) do
    Conn.put_resp_cookie(
      conn,
      cookie_key(client),
      refresh_token,
      http_only: true,
      max_age: JwtHelpers.token_expiration(refresh_token) |> Date.diff_now()
    )
  end

  defp delete_refresh_token(conn, client) do
    Conn.delete_resp_cookie(conn, cookie_key(client))
  end

  defp cookie_key(client) do
    get_in(Application.get_env(:web_auth, :clients), [client, :refresh_token_cookie_key]) || Atom.to_string(client) <> "_rt"
  end
end
