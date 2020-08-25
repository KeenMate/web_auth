defmodule KeenAuth.Request do
  alias Plug.Conn

  @access_claims_key :access_claims

  def has_claims?(conn, _client) do
    Map.has_key?(conn.private, @access_claims_key)
  end

  def get_claims(%Conn{private: %{@access_claims_key => claims}}, _client) do
    claims
  end

  def put_claims(conn, claims, _client) do
    Conn.put_private(conn, @access_claims_key, claims)
  end

  def delete_claims(conn, _client) do
    update_in(conn.private, &Map.drop(&1, [@access_claims_key]))
  end

  def fetch_bearer_token(conn, _client) do
    case Conn.get_req_header(conn, "authorization") do
      [bearer_token | []] when is_binary(bearer_token) -> {:ok, bearer_token}
      _ -> {:error, :token_not_found}
    end
  end
end
