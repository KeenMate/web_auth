defmodule WebAuth.Helpers.JwtHelpers do
  require Logger

  def validate_claims(%{"exp" => exp, "aud" => aud}, valid_audience) when is_binary(valid_audience) do
    with :ok <- not_expired?(exp),
         :ok <- valid_audience?(aud, valid_audience) do
      :ok
    else
      {:error, reason} = error ->
        Logger.debug("Invalid claims, reason: #{inspect(reason)}")
        error
    end
  end

  def token_expiration(token) do
    with {:ok, %{"exp" => exp}} <- decode_paylod(token) do
      exp
    end
  end

  defp decode_paylod(token) when is_binary(token) do
    with [_algorithm, payload, _signature] <- String.split(token, "."),
         {:ok, decoded_payload} <- Base.url_decode64(payload, padding: false),
         {:ok, claims} <- Jason.decode(decoded_payload) do
      {:ok, claims}
    end
  end

  defp not_expired?(expiration) when is_number(expiration) do
    {:ok, exp_date} = DateTime.from_unix(expiration, :second, Calendar.ISO)
    current_date = DateTime.now!("Etc/UTC")

    Logger.debug("JWT expiration: #{expiration}, JWT date: #{exp_date}, current date: #{current_date}")

    if DateTime.diff(exp_date, current_date) > 0 do
      :ok
    else
      {:error, :expired}
    end
  end

  defp valid_audience?(audience, valid_audience) when is_binary(audience) and is_binary(valid_audience) do
    if audience == valid_audience do
      :ok
    else
      {:error, :invalid_audience}
    end
  end

  defp valid_audience?(audiences, valid_audience) when is_list(audiences) and is_binary(valid_audience) do
    if Enum.any?(audiences, &(&1 == valid_audience)) do
      :ok
    else
      {:error, :invalid_audience}
    end
  end
end
