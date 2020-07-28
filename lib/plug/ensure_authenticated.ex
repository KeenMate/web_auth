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

  def call(conn, _params) do
    if Tokens.access_claims_in_private?(conn) do
      conn
    else
      conn
      |> Conn.put_status(401)
    end
  end
end
