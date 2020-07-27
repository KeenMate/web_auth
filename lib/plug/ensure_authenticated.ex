defmodule WebAuth.Plug.EnsureAuthenticated do
  @moduledoc """
    Checks whether connection contains any claims in private or connection's session
    Redirects to login page otherwise
  """

  require Logger

  alias WebAuth.Tokens
  alias Plug.Conn

  def init(params) do
    params
  end

  #  def call(%Conn{private: %{claims: _}} = conn, _params) do
  #    Logger.debug("[EnsureAuthenticated]: Claims found in private. User is authenticated")
  #    conn
  #  end

  def call(conn, _params) do
    case {Tokens.access_claims_in_private?(conn), Tokens.access_claims_in_session?(conn)} do
      # {true, true} ->
      # log_claims(conn)

      {false, true} ->
        conn
        |> from_session_to_private()

      # |> log_claims()

      # {true, false} ->
      # log_claims(conn)

      {false, false} ->
        Logger.warn("No claims in private nor session. Setting 401 Unauthorized.")

        conn
        |> Conn.put_status(401)

      {_, _} ->
        conn
    end
  end

  defp from_session_to_private(conn) do
    id_claims = Tokens.get_id_claims_from_session(conn)
    access_claims = Tokens.get_access_claims_from_session(conn)

    conn
    |> Tokens.put_claims_into_private(id_claims, access_claims)
  end

  # defp log_claims(conn) do
  #   Logger.debug("""
  #   [AccessTokenAuth]: Access claims are in private so no access token from header is extracted
  #   \tCurrent id claims: #{inspect(Tokens.get_id_claims_from_private(conn))}
  #   \tCurrent access claims: #{inspect(Tokens.get_access_claims_from_private(conn))}
  #   """)

  #   conn
  # end
end
