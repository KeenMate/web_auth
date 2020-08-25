defmodule KeenAuth.Helpers.JwtHelpers do
  require Logger

  def token_expiration(token) do
    with {:ok, %{"exp" => exp}} <- decode_paylod(token) do
      {:ok, exp}
    end
  end

  defp decode_paylod(token) when is_binary(token) do
    with [_algorithm, payload, _signature] <- String.split(token, "."),
         {:ok, decoded_payload} <- Base.url_decode64(payload, padding: false),
         {:ok, claims} <- Jason.decode(decoded_payload) do
      {:ok, claims}
    end
  end
end
