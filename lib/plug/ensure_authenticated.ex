defmodule WebAuth.Plug.EnsureAuthenticated do
  @moduledoc """
    Checks whether connection contains any claims in private or connection's session
    Redirects to login page otherwise
  """

  require Logger

  alias WebAuth.Request
  alias Plug.Conn

  def init(params) do
    %{client: Keyword.fetch!(params, :client)}
  end

  def call(conn, %{client: client}) do
    if Request.has_claims?(conn, client) do
      conn
    else
      Conn.put_status(conn, 401)
    end
  end
end
