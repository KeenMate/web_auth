defmodule WebAuth.Tokens do
  @moduledoc """
  This module contains helper functions useful for managing tokens and claims for Conn
  """

  require Logger

  alias Plug.Conn

  @id_token_key :id_token
  @access_token_key :access_token
  @refresh_token_key :refresh_token

  @id_claims_key :id_claims
  @access_claims_key :access_claims

  @type claims() :: map() | nil

  def get_id_token_from_session(conn) do
    conn
    |> Conn.get_session(@id_token_key)
  end

  def get_access_token_from_session(conn) do
    conn
    |> Conn.get_session(@access_token_key)
  end

  @spec get_id_token_from_private(Conn.t()) :: binary() | nil
  def get_id_token_from_private(%Conn{private: %{@id_token_key => id_token}}), do: id_token

  def get_id_token_from_private(_conn), do: nil

  @spec get_access_token_from_private(Conn.t()) :: binary() | nil
  def get_access_token_from_private(%Conn{private: %{@access_token_key => access_token}}),
    do: access_token

  def get_access_token_from_private(_conn), do: nil

  @spec get_id_claims_from_session(Conn.t()) :: claims()
  def get_id_claims_from_session(conn) do
    conn
    |> Conn.get_session(@id_claims_key)
  end

  @spec get_id_claims_from_private(Conn.t()) :: claims()
  def get_id_claims_from_private(%Conn{private: %{@id_claims_key => id_claims}}) do
    id_claims
  end

  def get_id_claims_from_private(_conn), do: nil

  @spec get_access_claims_from_session(Conn.t()) :: claims()
  def get_access_claims_from_session(conn) do
    conn
    |> Conn.get_session(@access_claims_key)
  end

  @spec get_access_claims_from_private(Conn.t()) :: claims()
  def get_access_claims_from_private(%Conn{private: %{@access_claims_key => access_claims}}) do
    access_claims
  end

  def get_access_claims_from_private(_conn), do: nil

  @doc """
  If data is falsy value, assignment is skipped for that information
  """
  @spec put_tokens_into_session(Conn.t(), map()) :: Conn.t()
  def put_tokens_into_session(conn, tokens) do
    conn
    |> put_id_token_into_session(tokens)
    |> put_access_token_into_session(tokens)
    |> put_refresh_token_into_session(tokens)
  end

  @doc """
  If data is falsy value, assignment is skipped for that information
  """
  @spec put_claims_into_session(Conn.t(), map() | nil, map() | nil) :: Conn.t()
  def put_claims_into_session(conn, id_claims, access_claims) do
    with_id_conn = (id_claims && Conn.put_session(conn, @id_claims_key, id_claims)) || conn

    with_access_conn =
      (access_claims && Conn.put_session(with_id_conn, @access_claims_key, access_claims)) ||
        with_id_conn

    with_access_conn
  end

  @doc """
  If data is falsy value, assignment is skipped for that information
  """
  @spec put_claims_into_private(Conn.t(), map() | nil, map() | nil) :: Conn.t()
  def put_claims_into_private(conn, id_claims, access_claims) do
    with_id_conn = (id_claims && Conn.put_private(conn, @id_claims_key, id_claims)) || conn

    with_access_conn =
      (access_claims && Conn.put_private(with_id_conn, @access_claims_key, access_claims)) || conn

    with_access_conn
  end

  @spec id_token_in_private?(Conn.t()) :: boolean()
  def id_token_in_private?(conn) do
    (conn.private[@id_token_key] &&
       true) ||
      false
  end

  @spec id_token_in_session?(Conn.t()) :: boolean()
  def id_token_in_session?(conn) do
    (conn
     |> Conn.get_session(@id_token_key) &&
       true) ||
      false
  end

  @spec access_token_in_private?(Conn.t()) :: boolean()
  def access_token_in_private?(conn) do
    (conn.private[@access_token_key] &&
       true) ||
      false
  end

  @spec access_token_in_session?(Conn.t()) :: boolean()
  def access_token_in_session?(conn) do
    (conn
     |> Conn.get_session(@access_token_key) &&
       true) ||
      false
  end

  @spec id_claims_in_private?(Conn.t()) :: boolean()
  def id_claims_in_private?(conn) do
    (conn.private[@id_claims_key] &&
       true) ||
      false
  end

  @spec id_claims_in_session?(Conn.t()) :: boolean()
  def id_claims_in_session?(conn) do
    (conn
     |> Conn.get_session(@id_claims_key) &&
       true) ||
      false
  end

  @spec access_claims_in_private?(Conn.t()) :: boolean()
  def access_claims_in_private?(conn) do
    (conn.private[@access_claims_key] &&
       true) ||
      false
  end

  @spec access_claims_in_session?(Conn.t()) :: boolean()
  def access_claims_in_session?(conn) do
    (conn
     |> Conn.get_session(@access_claims_key) &&
       true) ||
      false
  end

  defp put_id_token_into_session(conn, %{"id_token" => token}) do
    conn
    |> Conn.put_session(@id_token_key, token)
  end

  defp put_id_token_into_session(conn, _tokens) do
    Logger.warn(
      "Key 'id_token' was not found in tokens map while storing them inside conn's session"
    )

    conn
  end

  defp put_refresh_token_into_session(conn, %{"refresh_token" => token}) do
    conn
    |> Conn.put_session(@refresh_token_key, token)
  end

  defp put_refresh_token_into_session(conn, _tokens) do
    Logger.warn(
      "Key 'refresh_token' was not found in tokens map while storing them inside conn's session"
    )

    conn
  end

  defp put_access_token_into_session(conn, %{"access_token" => token}) do
    conn
    |> Conn.put_session(@access_token_key, token)
  end

  defp put_access_token_into_session(conn, _tokens) do
    Logger.warn(
      "Key 'access_token' was not found in tokens map while storing them inside conn's session"
    )

    conn
  end
end
